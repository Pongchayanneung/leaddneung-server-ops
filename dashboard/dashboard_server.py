#!/usr/bin/env python3
"""Dashboard + command console server for leaddneung.
- GET /            -> status dashboard (index.html)
- GET /status.json -> live metrics (read-only, safe)
- GET /console     -> command console page
- POST /command    -> runs `claude -p` on the server (SECRET-gated, audited)

Security: secret-token gate, kill-switch flag, concurrency=1, timeout,
per-window rate limit, output redaction, append audit log. Runs as the login
user (sudo stays password-gated, so root fixes are naturally bounded).
"""
import hmac
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
QUEUE_STATUS = os.path.join(HOME, "transcribe-queue", "status.json")
SECRET_FILE = os.path.join(ROOT, ".command_secret")
ENABLED_FLAG = os.path.join(ROOT, "COMMAND_ENABLED")   # rm this = kill switch
AUDIT_LOG = os.path.join(ROOT, "command-audit.log")
CLAUDE_BIN = os.path.join(HOME, ".local", "bin", "claude")

CMD_TIMEOUT = 180          # seconds per command
MSG_MAX = 4096             # max message length
RATE_WINDOW, RATE_MAX = 300, 15  # <=15 commands / 5 min

_cmd_lock = threading.Lock()   # concurrency = 1
_rate_hits = []                # timestamps of recent commands

# redact obvious secrets from any output before returning it
_REDACT = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"
    r"|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,})",
    re.DOTALL,
)


def _run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception:
        return ""


# ----- metrics (read-only) -------------------------------------------------
def cpu_pct():
    def snap():
        with open("/proc/stat") as f:
            p = [int(x) for x in f.readline().split()[1:]]
        return sum(p), p[3] + p[4]
    t1, i1 = snap()
    time.sleep(0.15)
    t2, i2 = snap()
    dt, di = t2 - t1, i2 - i1
    return round(100 * (dt - di) / dt, 1) if dt else 0.0


def mem():
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":")
            info[k] = int(v.split()[0])
    total = info["MemTotal"] / 1024 / 1024
    avail = info.get("MemAvailable", info["MemFree"]) / 1024 / 1024
    used = total - avail
    return {"used_gb": round(used, 1), "total_gb": round(total, 1),
            "pct": round(100 * used / total) if total else 0}


def gpu():
    out = _run(["nvidia-smi",
                "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
                "--format=csv,noheader,nounits"])
    if not out:
        return {"name": "GPU", "util_pct": 0, "mem_used_mb": 0, "mem_total_mb": 0, "temp_c": 0, "power_w": 0}
    p = [x.strip() for x in out.split(",")]
    return {"name": p[0].replace("NVIDIA GeForce ", "").replace(" Laptop GPU", ""),
            "util_pct": float(p[1]), "mem_used_mb": int(float(p[2])), "mem_total_mb": int(float(p[3])),
            "temp_c": int(float(p[4])), "power_w": round(float(p[5]))}


def svc_active(name, user=False):
    cmd = ["systemctl", "--user", "is-active", name] if user else ["systemctl", "is-active", name]
    return _run(cmd) == "active"


def cpu_temp():
    """CPU package temperature in C (AMD k10temp / Intel coretemp), or None."""
    base = "/sys/class/hwmon"
    try:
        for h in os.listdir(base):
            try:
                name = open(os.path.join(base, h, "name")).read().strip()
            except OSError:
                continue
            if name in ("k10temp", "coretemp", "zenpower"):
                for f in sorted(os.listdir(os.path.join(base, h))):
                    if f.startswith("temp") and f.endswith("_input"):
                        v = int(open(os.path.join(base, h, f)).read().strip())
                        return round(v / 1000)
    except Exception:
        pass
    return None


def power():
    """Wall power + battery. For a laptop-as-server, 'ac False' = imminent death."""
    ps = "/sys/class/power_supply"
    ac, cap, status = None, None, None
    try:
        for d in os.listdir(ps):
            p = os.path.join(ps, d)
            try:
                typ = open(os.path.join(p, "type")).read().strip()
            except OSError:
                continue
            if typ == "Mains":
                try:
                    ac = open(os.path.join(p, "online")).read().strip() == "1"
                except OSError:
                    pass
            elif typ == "Battery":
                try:
                    cap = int(open(os.path.join(p, "capacity")).read().strip())
                except OSError:
                    pass
                try:
                    status = open(os.path.join(p, "status")).read().strip()
                except OSError:
                    pass
    except Exception:
        pass
    return {"ac": ac, "battery_pct": cap, "status": status}


def _human_users():
    """Names of real login users (uid>=1000 with a shell)."""
    users = set()
    try:
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) >= 7:
                    try:
                        uid = int(parts[2])
                    except ValueError:
                        continue
                    shell = parts[6].strip().split("/")[-1]
                    if 1000 <= uid < 65000 and shell in ("bash", "sh", "zsh", "fish"):
                        users.add(parts[0])
    except Exception:
        pass
    return users


def activity():
    """Who is using the box: logged-in users + their load, GPU jobs, current file."""
    humans = _human_users()
    sessions = {}
    for line in _run(["who"]).splitlines():
        parts = line.split()
        if parts:
            sessions[parts[0]] = sessions.get(parts[0], 0) + 1
    stats = {}
    for line in _run(["ps", "-eo", "user:32,pcpu", "--no-headers"]).splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            try:
                c = float(parts[1])
            except ValueError:
                c = 0.0
            s = stats.setdefault(parts[0], {"cpu": 0.0, "procs": 0})
            s["cpu"] += c
            s["procs"] += 1
    users = []
    for name in humans:
        st = stats.get(name, {"cpu": 0.0, "procs": 0})
        online = sessions.get(name, 0)
        if online or st["procs"] > 0:
            users.append({"user": name, "sessions": online,
                          "cpu": round(st["cpu"], 1), "procs": st["procs"]})
    users.sort(key=lambda x: (-x["sessions"], -x["cpu"]))

    gpu_procs = []
    for line in _run(["nvidia-smi", "--query-compute-apps=pid,used_memory",
                      "--format=csv,noheader,nounits"]).splitlines():
        parts = [x.strip() for x in line.split(",")]
        if len(parts) >= 2 and parts[0].isdigit():
            owner = _run(["ps", "-o", "user=", "-p", parts[0]]) or "?"
            try:
                memmb = int(float(parts[1]))
            except ValueError:
                memmb = 0
            gpu_procs.append({"pid": int(parts[0]), "user": owner, "vram_mb": memmb})

    current_job = None
    try:
        workdir = os.path.join(HOME, "transcribe-queue", "work")
        for fn in os.listdir(workdir):
            if fn.endswith(".16k.wav"):
                current_job = fn[:-len(".16k.wav")]
                break
    except Exception:
        pass
    return {"users": users, "gpu_procs": gpu_procs,
            "current_job": current_job, "job_running": bool(current_job)}


def build_status():
    with open("/proc/uptime") as f:
        up = int(float(f.readline().split()[0]))
    d, rem = divmod(up, 86400)
    h, rem = divmod(rem, 3600)
    uptime = (f"{d} days, " if d else "") + f"{h}:{rem // 60:02d}"
    du = shutil.disk_usage("/")
    disk = {"used_gb": round(du.used / 1e9), "total_gb": round(du.total / 1e9),
            "pct": round(100 * du.used / du.total)}
    ts_raw = _run(["tailscale", "status"])
    ts_ok = ts_raw != "" and "stopped" not in ts_raw.lower()
    ts_ip = _run(["tailscale", "ip", "-4"]).splitlines()[0] if ts_ok else ""
    queue = {"pending": 0, "processing": 0, "done": 0}
    try:
        with open(QUEUE_STATUS) as f:
            q = json.load(f)
            queue = {k: q.get(k, 0) for k in ("pending", "processing", "done")}
    except Exception:
        pass
    g, r = gpu(), mem()
    act = activity()
    pw = power()
    queue["current"] = act.get("current_job")
    services = [
        {"name": "transcribe-queue", "active": svc_active("transcribe-queue.service", user=True)},
        {"name": "netdata", "active": svc_active("netdata")},
        {"name": "tailscaled", "active": svc_active("tailscaled")},
    ]
    alerts = []
    if disk["pct"] >= 90:
        alerts.append({"level": "crit", "msg": f"Disk {disk['pct']}%"})
    if r["pct"] >= 92:
        alerts.append({"level": "crit", "msg": f"RAM {r['pct']}%"})
    if g["temp_c"] >= 90:
        alerts.append({"level": "crit", "msg": f"GPU {g['temp_c']}C"})
    # laptop-as-server: running on battery means it will die when it drains
    if pw.get("ac") is False:
        bp = pw.get("battery_pct")
        alerts.append({"level": "crit",
                       "msg": f"On battery — AC unplugged" + (f" ({bp}%)" if bp is not None else "")})
    for s in services:
        if not s["active"]:
            alerts.append({"level": "warn", "msg": f"{s['name']} down"})
    if not ts_ok:
        alerts.append({"level": "crit", "msg": "Tailscale down"})
    return {"hostname": socket.gethostname(), "updated_at": int(time.time()), "uptime": uptime,
            "cpu_pct": cpu_pct(), "cpu_temp": cpu_temp(),
            "load": [float(x) for x in open("/proc/loadavg").read().split()[:3]],
            "ram": r, "disk": disk, "gpu": g, "power": pw, "activity": act,
            "tailscale": {"status": "connected" if ts_ok else "down", "ip": ts_ip},
            "queue": queue, "services": services, "alerts": alerts}


# 2s snapshot cache: build_status() forks several subprocesses; this caps the
# work when multiple viewers (owner + shared collaborator) poll concurrently.
_status_cache = {"ts": 0.0, "data": None}
_status_lock = threading.Lock()
STATUS_TTL = 2.0


def _redact_public(data):
    """Shared/read-only view: hide job CONTENT (transcript filename), keep infra.
    Returns a shallow copy with only the sensitive fields blanked (immutable)."""
    d = dict(data)
    act = dict(d.get("activity") or {})
    if act.get("current_job"):
        act["current_job"] = None      # job_running stays True -> UI shows "processing"
    d["activity"] = act
    q = dict(d.get("queue") or {})
    if q.get("current"):
        q["current"] = None
    d["queue"] = q
    return d


def get_status(public=False):
    now = time.time()
    with _status_lock:
        if not _status_cache["data"] or now - _status_cache["ts"] > STATUS_TTL:
            _status_cache["data"] = build_status()
            _status_cache["ts"] = now
        data = _status_cache["data"]
    return _redact_public(data) if public else data


# ----- command console (privileged) ----------------------------------------
def _secret():
    try:
        with open(SECRET_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def _audit(ip, msg, result):
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps({"ts": int(time.time()), "ip": ip,
                                "msg": msg[:500], "result": result}) + "\n")
    except Exception:
        pass


def _rate_ok():
    now = time.time()
    _rate_hits[:] = [t for t in _rate_hits if now - t < RATE_WINDOW]
    if len(_rate_hits) >= RATE_MAX:
        return False
    _rate_hits.append(now)
    return True


def run_command(message, ip):
    if not os.path.exists(ENABLED_FLAG):
        _audit(ip, message, "disabled")
        return 503, {"error": "command console disabled (kill switch)"}
    if not _rate_ok():
        _audit(ip, message, "rate-limited")
        return 429, {"error": "rate limited"}
    if not _cmd_lock.acquire(blocking=False):
        return 429, {"error": "busy (another command running)"}
    try:
        started = time.time()
        env = dict(os.environ, PATH=os.path.join(HOME, ".local/bin") + ":" + os.environ.get("PATH", ""))
        proc = subprocess.run(
            [CLAUDE_BIN, "-p", "--dangerously-skip-permissions", message],
            capture_output=True, text=True, timeout=CMD_TIMEOUT, cwd=HOME, env=env,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        out = _REDACT.sub("[REDACTED]", out)[:20000]
        _audit(ip, message, f"exit={proc.returncode} dur={time.time()-started:.0f}s")
        return 200, {"output": out, "exit": proc.returncode}
    except subprocess.TimeoutExpired:
        _audit(ip, message, "timeout")
        return 504, {"error": f"timed out after {CMD_TIMEOUT}s"}
    except Exception as err:
        _audit(ip, message, f"error={err}")
        return 500, {"error": str(err)}
    finally:
        _cmd_lock.release()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def _file(self, name, ctype):
        try:
            with open(os.path.join(ROOT, name), "rb") as f:
                return self._send(200, ctype, f.read())
        except FileNotFoundError:
            self.send_error(404)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        if path in ("", "/index.html"):
            return self._file("index.html", "text/html; charset=utf-8")
        if path == "/monitor":
            # read-only shared view (same page; console UI hidden client-side)
            return self._file("index.html", "text/html; charset=utf-8")
        if path == "/console":
            return self._file("console.html", "text/html; charset=utf-8")
        if path == "/netdata":
            host = self.headers.get("Host", "leaddneung:8080").split(":")[0]
            self.send_response(302)
            self.send_header("Location", f"http://{host}:19999/")
            self.end_headers()
            return
        if path == "/status.json":
            return self._send(200, "application/json", json.dumps(get_status(public=False)))
        if path == "/status.pub.json":
            # redacted feed for the shared /monitor view (no job filenames)
            return self._send(200, "application/json", json.dumps(get_status(public=True)))
        self.send_error(404)

    def do_POST(self):
        if self.path.split("?")[0] != "/command":
            return self.send_error(404)
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._send(400, "application/json", json.dumps({"error": "bad request"}))
        secret, message = _secret(), (data.get("message") or "").strip()
        if not secret or not hmac.compare_digest(str(data.get("secret", "")), secret):
            _audit(self.client_address[0], message, "auth-fail")
            return self._send(403, "application/json", json.dumps({"error": "forbidden"}))
        if not message or len(message) > MSG_MAX:
            return self._send(400, "application/json", json.dumps({"error": "empty or too long"}))
        code, body = run_command(message, self.client_address[0])
        self._send(code, "application/json", json.dumps(body))


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
