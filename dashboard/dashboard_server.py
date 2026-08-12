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
import sqlite3
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


_GPU_UNKNOWN = {"name": "GPU", "util_pct": 0, "mem_used_mb": 0,
                "mem_total_mb": 0, "temp_c": 0, "power_w": 0, "ok": False}


def gpu():
    """GPU stats, or a safe placeholder if nvidia-smi misbehaves.

    Hardened 2026-08-07: a saturated GPU makes nvidia-smi slow and sometimes
    makes it emit a warning or a truncated row. Indexing that blindly raised
    IndexError inside build_status(), which took /status.json down entirely --
    the dashboard went blind exactly when the machine was busiest, which is
    when you most need it. Never let a flaky subprocess kill the whole page.
    """
    # 5s is not enough while the GPU is pinned; nvidia-smi queues behind work.
    out = _run(["nvidia-smi",
                "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
                "--format=csv,noheader,nounits"], timeout=20)
    if not out:
        return dict(_GPU_UNKNOWN)
    # Take the first device row only, and require every field to be present.
    p = [x.strip() for x in out.splitlines()[0].split(",")]
    if len(p) < 6:
        return dict(_GPU_UNKNOWN)
    try:
        return {"name": p[0].replace("NVIDIA GeForce ", "").replace(" Laptop GPU", ""),
                "util_pct": float(p[1]), "mem_used_mb": int(float(p[2])),
                "mem_total_mb": int(float(p[3])), "temp_c": int(float(p[4])),
                "power_w": round(float(p[5])), "ok": True}
    except ValueError:
        # e.g. "[N/A]" in a field while the driver is under pressure
        return dict(_GPU_UNKNOWN)


# ----- GPU clocks and throttling -------------------------------------------
# Ported 2026-08-11 from the retired ~/server-monitor/collectors/gpu.py, which
# was the only thing on this box that ever showed throttle state. Thermal is the
# documented limiting factor here (the vBIOS ignores `-pl`, so gpu-clock-cap.service
# pins the clock with `-lgc` instead), and until now there was no way to see whether
# that cap was holding.
#
# DELIBERATELY A SEPARATE nvidia-smi CALL from gpu(). The driver renamed these
# fields (`clocks_throttle_reasons.*` -> `clocks_event_reasons.*`; 595.84 still
# accepts the old names as input, which is why the old names are used here for
# the widest compatibility). If a future driver drops that alias, this query dies.
# Folding it into gpu()'s query would then blank the whole GPU tile, turning a
# nice-to-have into a regression. Isolated, a break costs only this section.
_GPU_CLOCK_FIELDS = [
    "clocks.sm", "clocks.max.sm",
    "clocks_throttle_reasons.sw_thermal_slowdown",
    "clocks_throttle_reasons.hw_thermal_slowdown",
    "clocks_throttle_reasons.sw_power_cap",
]

# `nvidia-smi -q` is far heavier than --query-gpu, and the cap only changes when a
# unit file does, so both are refreshed on a slow timer instead of every 2s poll.
_GPU_SLOW_TTL = 60.0
_gpu_slow_cache = {"ts": 0.0, "data": {}}
# This is a ThreadingHTTPServer. The cache happens to be safe today only because its
# single caller sits inside _status_lock, which is an invariant nothing enforces and
# the next caller would quietly break. Owning a lock costs nothing here.
_gpu_slow_lock = threading.Lock()


def _flag(value):
    return value.strip().lower() in ("active", "1", "true")


def _gpu_clock_cap():
    """The applied `-lgc` ceiling in MHz, or None if no cap is in force.

    The lock set by `nvidia-smi -lgc` appears NOWHERE in `nvidia-smi -q` on driver
    595.84, so it has to be read back off the unit that sets it. This matters a
    lot for honesty: clocks.max.sm reports the HARDWARE max (2100 MHz), so showing
    current/max would render the intended 1500 MHz ceiling as a permanent "71%"
    and read as constant throttling. Percentages here are against the cap when one
    is active, and the hardware max is kept alongside as context.
    """
    if _run(["systemctl", "is-active", "gpu-clock-cap.service"]) != "active":
        return None
    unit = _run(["systemctl", "cat", "gpu-clock-cap.service"])
    # Accept every spelling nvidia-smi does. A stricter pattern silently returns
    # None on a legitimate variant, which does not fail loudly: it falls back to the
    # 2100 MHz hardware max and renders a correctly capped GPU as permanently
    # throttled, i.e. precisely the bug this function exists to prevent.
    #   -lgc 300,1500 | -lgc 300, 1500 | -lgc 1500 | --lock-gpu-clocks=300,1500
    match = re.search(r"(?:-lgc|--lock-gpu-clocks)[\s=]+(\d+)(?:\s*,\s*(\d+))?", unit)
    if not match:
        return None
    # Range form gives min,max so the ceiling is the second value; the single-value
    # form locks to one clock, which is itself the ceiling.
    return int(match.group(2) or match.group(1))


def _gpu_throttle_counters():
    """Cumulative microseconds the driver has spent in each throttle state.

    Worth more than the instantaneous flags: a spot check almost never lands on a
    slowdown, but the counter says whether it has been happening at all. These are
    since driver load, so they only ever climb; the UI shows them as totals, not
    as a rate.
    """
    out = _run(["nvidia-smi", "-q", "-d", "PERFORMANCE"], timeout=20)
    if not out:
        return {}
    wanted = {"SW Power Capping": "power_us", "SW Thermal Slowdown": "thermal_sw_us",
              "HW Thermal Slowdown": "thermal_hw_us"}
    found, header_indent = {}, None
    for line in out.splitlines():
        if header_indent is None:
            if ("Clocks Event Reasons Counters" in line
                    or "Clocks Throttle Reasons Counters" in line):
                header_indent = len(line) - len(line.lstrip())
            continue
        # Scope by indentation and stop at the first section that is not deeper than
        # the header. Reading "until something looks wrong" let a multi-GPU report
        # run straight past device 0's block, so device N's counters overwrote it
        # and were then shown beside device 0's live flags. Only the first device is
        # parsed, matching gpu_clocks(), which also takes the first row only.
        if line.strip() and (len(line) - len(line.lstrip())) <= header_indent:
            break
        label, _, value = line.partition(":")
        if label.strip() in wanted:
            digits = re.match(r"(\d+)", value.strip())
            if digits:
                found[wanted[label.strip()]] = int(digits.group(1))
    return found


def _gpu_slow():
    with _gpu_slow_lock:
        now = time.time()
        if now - _gpu_slow_cache["ts"] > _GPU_SLOW_TTL:
            try:
                _gpu_slow_cache["data"] = {"cap_mhz": _gpu_clock_cap(),
                                           "counters": _gpu_throttle_counters()}
            except Exception:
                _gpu_slow_cache["data"] = {}
            _gpu_slow_cache["ts"] = now
        return _gpu_slow_cache["data"]


def gpu_clocks():
    """Clock headroom and throttle state. {"ok": False} if unavailable.

    NOTE gpu_idle is intentionally NOT treated as throttling. It is reported as a
    clocks-event reason and is Active whenever the box is quiet, so counting it
    would paint an idle machine as permanently throttled. Only thermal and power
    slowdowns mean something is being taken away from you.
    """
    out = _run(["nvidia-smi", f"--query-gpu={','.join(_GPU_CLOCK_FIELDS)}",
                "--format=csv,noheader,nounits"], timeout=20)
    if not out:
        return {"ok": False}
    p = [x.strip() for x in out.splitlines()[0].split(",")]
    if len(p) < len(_GPU_CLOCK_FIELDS):
        return {"ok": False}
    try:
        cur, hw_max = int(float(p[0])), int(float(p[1]))
    except ValueError:
        return {"ok": False}

    slow = _gpu_slow()
    cap = slow.get("cap_mhz")
    ceiling = cap or hw_max
    counters = slow.get("counters", {})
    return {
        "ok": True,
        "mhz": cur,
        "cap_mhz": cap,
        "max_mhz": hw_max,
        "pct_of_ceiling": round(cur / ceiling * 100) if ceiling else 0,
        "throttled_thermal": _flag(p[2]) or _flag(p[3]),
        "throttled_power": _flag(p[4]),
        # None, not 0, when the counters block could not be read. Defaulting to 0
        # renders "0s thermal" and reads as a confident "never throttled" when the
        # truth is "unknown" -- the same class of lie this whole feature was added
        # to remove. The UI shows None as "lifetime totals unavailable".
        "thermal_secs": (round((counters["thermal_sw_us"] + counters["thermal_hw_us"]) / 1e6)
                         if "thermal_sw_us" in counters and "thermal_hw_us" in counters
                         else None),
        "power_secs": (round(counters["power_us"] / 1e6)
                       if "power_us" in counters else None),
    }


def svc_active(name, user=False):
    cmd = ["systemctl", "--user", "is-active", name] if user else ["systemctl", "is-active", name]
    return _run(cmd) == "active"


# At most this many unit names are spelled out in one alert. Past four the line
# stops fitting a phone-width card, and a mass failure is a "go and look at the
# box" event rather than something you triage from the banner. The remainder is
# always COUNTED in the message, never silently dropped.
ALERT_MAX_NAMED_UNITS = 4


def failed_units():
    """NAMES of the systemd units in the failed state (system + user) — a generic
    net that catches ANY unit failing, not just the named ones.

    Returns a list; the count is len(). It used to return only the count, which
    rendered as "2 systemd unit(s) failed" and forced an ssh to find out which.
    That is the same unnamed-alert weakness already removed from
    ~/transcribe-opt/health-watchdog.sh, whose pings are now titled
    "leaddneung: <unit> failed"; the dashboard was left behind. The names are
    free: both subprocesses were ALREADY printing them and the old code threw
    the text away just to count lines.

    A name is scope-tagged only when the SAME unit name is failed in both
    scopes, which is the only case where a bare name is ambiguous.
    """
    found = []
    for scope, cmd in (("system", ["systemctl", "--failed", "--no-legend", "--plain"]),
                       ("user", ["systemctl", "--user", "--failed", "--no-legend", "--plain"])):
        for line in _run(cmd).splitlines():
            parts = line.split()
            if parts:
                found.append((parts[0], scope))
    names = [n for n, _ in found]
    return [f"{n} ({s})" if names.count(n) > 1 else n for n, s in found]


def failed_units_msg(units):
    """One alert line that says WHICH units failed, truncated but never silently.

    One unit reads as a sentence ("offsite-backup.service failed"); several lead
    with the count so the scale of the problem is the first thing read.
    """
    total = len(units)
    if total == 1:
        return f"{units[0]} failed"
    shown = units[:ALERT_MAX_NAMED_UNITS]
    omitted = total - len(shown)
    return (f"{total} units failed: " + ", ".join(shown)
            + (f" (+{omitted} more)" if omitted else ""))


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


def fans():
    """Fan RPMs from the ASUS EC (fan1=CPU, fan2=GPU), e.g. {"cpu": 3100, "gpu": 0}."""
    base = "/sys/class/hwmon"
    out = {}
    try:
        for h in os.listdir(base):
            try:
                name = open(os.path.join(base, h, "name")).read().strip()
            except OSError:
                continue
            if name == "asus":
                for f in sorted(os.listdir(os.path.join(base, h))):
                    if f.startswith("fan") and f.endswith("_input"):
                        try:
                            rpm = int(open(os.path.join(base, h, f)).read().strip())
                        except (OSError, ValueError):
                            continue
                        idx = f[3:f.index("_")]
                        out[{"1": "cpu", "2": "gpu"}.get(idx, idx)] = rpm
    except Exception:
        pass
    return out


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


POWER_SNAPSHOT = "/run/power-meter/metrics"
POWER_STALE_AFTER = 60          # seconds; older means power-meter.service is down
TRANSCRIBE_LOG = os.path.join(HOME, "transcribe-queue", "daemon.log")
TRANSCRIBE_RECENT = 20          # jobs used for the CURRENT rate
# NOMINAL_BUSY_WATTS moved down to the busy-wattage block, next to the measured
# figure that now supersedes it. See busy_watts().
# Two formats, both live in the same log file forever.
#   pre  2026-08-12: "... 56.6s audio, 8.9s proc, rtf=0.157"
#   post 2026-08-12: "... dur=180.0s, vad_speech=11.8s, covered=118.7s
#                     (65.9% of duration), proc=28.5s, rtf=0.158, method=..."
# The daemon relabelled its numbers because the old "Ns audio" was actually
# VAD speech, not duration -- it under-reported a 6754.6s lecture as 1548.7s.
# Match both: dropping the old branch would silently zero out years of history,
# and dropping the new one would silently freeze this panel at 2026-08-12.
_DONE_LINE = re.compile(
    r"done .+?: \d+ segs, "
    r"(?:(?P<audio_old>[\d.]+)s audio, (?P<proc_old>[\d.]+)s proc"
    r"|dur=(?P<audio_new>[\d.]+)s,.*?proc=(?P<proc_new>[\d.]+)s)"
    r", rtf=(?P<rtf>[\d.]+)")


def power_meter():
    """Wall watts and electricity cost from power-meter.service.

    That sampler runs as root because the RAPL energy counter is mode 0400;
    it publishes a world-readable snapshot which is all this reads. Distinct
    from power() above, which reports AC/battery state rather than draw.
    """
    try:
        with open(POWER_SNAPSHOT) as f:
            raw = f.read()
    except OSError:
        return {"available": False}
    d = {}
    for line in raw.splitlines():
        k, _, v = line.partition("=")
        try:
            d[k.strip()] = float(v.strip())
        except ValueError:
            pass
    if time.time() - d.get("timestamp", 0) > POWER_STALE_AFTER:
        return {"available": False}
    return {
        "available": True,
        "watts": round(d.get("total_watts", 0), 1),
        "cpu_w": round(d.get("cpu_watts", 0), 1),
        "gpu_w": round(d.get("gpu_watts", 0), 1),
        "thb_per_hour": round(d.get("thb_per_hour", 0), 3),
        "thb_today": round(d.get("thb_today", 0), 2),
        "thb_month": round(d.get("thb_month", 0), 2),
        "thb_month_projected": round(d.get("thb_month_projected", 0), 2),
        "kwh_today": round(d.get("kwh_today", 0), 2),
        "thb_per_kwh": d.get("thb_per_kwh", 0),
    }


def transcribe_cost(tariff):
    """Electricity cost of transcription, from the daemon's own job log.

    Billed against PROCESSING time, not audio length: an hour of audio at
    rtf 0.25 only occupies the GPU for ~15 minutes. The rate uses only the
    most recent jobs, because the log reaches back to the slower plain-mode
    era and the lifetime median would overstate today's cost.

    The load figure comes from busy_watts(), which measures it from recorded
    history where it can. `watts_measured` says whether it did; when it is
    False every baht below rests on a nominal, not on an observation.
    """
    audio_s = proc_s = 0.0
    rtfs = []
    try:
        with open(TRANSCRIBE_LOG, errors="replace") as f:
            for m in _DONE_LINE.finditer(f.read()):
                audio_s += float(m.group("audio_old") or m.group("audio_new"))
                proc_s += float(m.group("proc_old") or m.group("proc_new"))
                rtfs.append(float(m.group("rtf")))
    except OSError:
        return {"available": False}
    if not rtfs or not tariff:
        return {"available": False}
    recent = rtfs[-TRANSCRIBE_RECENT:]
    recent.sort()
    median_rtf = recent[len(recent) // 2]
    bw = busy_watts()
    load_kw = bw["watts"] / 1000.0
    return {
        "available": True,
        "jobs": len(rtfs),
        "audio_hours": round(audio_s / 3600, 1),
        "proc_hours": round(proc_s / 3600, 1),
        "realtime_factor": round(1 / median_rtf, 1) if median_rtf else 0,
        "thb_per_audio_hour": round(median_rtf * load_kw * tariff, 3),
        "thb_total": round(proc_s / 3600 * load_kw * tariff, 2),
        # Provenance travels WITH the number. A consumer that shows the baht
        # without these is showing a figure it cannot vouch for.
        "busy_watts": bw["watts"],
        "watts_measured": bw["measured"],
        "watts_samples": bw["samples"],
        "watts_threshold_pct": bw["util_threshold_pct"],
        "watts_min_samples": bw["min_samples"],
    }


HISTORY_DB = os.path.join(ROOT, "history.db")
HISTORY_METRICS = ("watts", "thb_hr", "cpu_pct", "cpu_temp", "load1",
                   "ram_pct", "disk_pct", "gpu_util", "gpu_temp", "gpu_power",
                   "q_pending", "q_done")
HISTORY_MAX_POINTS = 400
HISTORY_MAX_HOURS = 24 * 90

# ===================== BUSY WATTAGE (measured, not assumed) =====================
# gpu_util at or above this counts as "the box is working". 50 is inherited from
# the retired ~/server-monitor collector (powerprofile.BUSY_UTILISATION), which
# learned this machine's busy draw the same way from live samples. The recorded
# history says the exact cut barely matters here: utilisation on this host is
# bimodal — of 6948 stored samples only 2 land anywhere in the whole 10–50% band —
# so 50 / 70 / 90 all return ~128 W. 50 is kept because it is the threshold the
# earlier cost figures were learned with, and because dropping lower would start
# folding idle minutes that caught one blip into the busy mean.
BUSY_UTIL_PCT = 50.0
# Under this many busy samples the mean is not evidence, so the nominal is used
# INSTEAD and the payload says so. Samples are one per minute, so 30 is half an
# hour of real GPU-busy time. The old in-memory collector accepted 6, which was
# defensible for a figure that re-sharpened every minute the process stayed up;
# this is a one-shot query against stored history that nothing revisits, so it
# asks for more evidence before it is allowed to call itself a measurement.
BUSY_MIN_SAMPLES = 30
# The nominal. Used ONLY when history cannot support a measured figure, and never
# without `measured: False` travelling alongside it.
NOMINAL_BUSY_WATTS = 160.0
# Same 60s slow-cache pattern as _gpu_slow(): this is a SQL aggregate over up to
# 90 days of rows and the status endpoint is polled every 2 seconds. Lock for the
# same reason too — ThreadingHTTPServer means concurrent viewers really do land
# here at once, and relying on a caller's lock is an invariant nothing enforces.
_BUSY_WATTS_TTL = 60.0
_busy_watts_cache = {"ts": 0.0, "data": None}
_busy_watts_lock = threading.Lock()


def _query_busy_watts():
    """(mean wall watts, sample count) over history taken while the GPU worked.

    Column note: the wall figure is `watts`. `gpu_power` is the card on its own
    and would undercount the box by roughly half. `watts > 0` drops the minutes
    when power-meter.service was down, which the recorder stores as 0 — averaging
    those in would quietly drag the mean toward zero and UNDERstate cost, the
    same class of silent wrongness as the nominal it replaces.
    """
    since = int(time.time()) - HISTORY_MAX_HOURS * 3600
    try:
        conn = sqlite3.connect(f"file:{HISTORY_DB}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return None, 0
    try:
        count, avg = conn.execute(
            "SELECT COUNT(*), AVG(watts) FROM samples "
            "WHERE ts >= ? AND gpu_util >= ? AND watts > 0",
            (since, BUSY_UTIL_PCT),
        ).fetchone()
    except sqlite3.Error:
        return None, 0
    finally:
        conn.close()
    return avg, int(count or 0)


def busy_watts():
    """Wattage to bill work against: {watts, measured, samples, ...}.

    `measured` False means the value IS the nominal and has not been observed on
    this machine. Presenting a nameplate number as if it had been measured — and
    presenting a mean of three samples as if it were solid — are the two specific
    dishonesties this function exists to remove, so no caller can get the value
    without also getting where it came from.
    """
    with _busy_watts_lock:
        now = time.time()
        if (_busy_watts_cache["data"] is None
                or now - _busy_watts_cache["ts"] > _BUSY_WATTS_TTL):
            try:
                avg, count = _query_busy_watts()
            except Exception:
                avg, count = None, 0
            ok = avg is not None and count >= BUSY_MIN_SAMPLES
            _busy_watts_cache["data"] = {
                "watts": round(avg, 1) if ok else NOMINAL_BUSY_WATTS,
                "measured": ok,
                "samples": count,
                "util_threshold_pct": BUSY_UTIL_PCT,
                "min_samples": BUSY_MIN_SAMPLES,
            }
            _busy_watts_cache["ts"] = now
        return _busy_watts_cache["data"]


def history_series(hours=24, max_points=HISTORY_MAX_POINTS):
    """Averaged series over the last `hours`, bucketed to at most max_points.

    Averaging in SQL rather than shipping every row keeps a 90-day window the
    same size on the wire as a 6-hour one. Buckets are clamped to a whole
    number of minutes because that is the sample interval.
    """
    hours = max(1, min(int(hours), HISTORY_MAX_HOURS))
    span = hours * 3600
    bucket = max(60, (span // max_points // 60) * 60 or 60)
    since = int(time.time()) - span
    cols = ", ".join(f"AVG({m}) AS {m}" for m in HISTORY_METRICS)
    try:
        conn = sqlite3.connect(f"file:{HISTORY_DB}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return {"available": False, "reason": "no history database yet"}
    try:
        rows = conn.execute(
            f"SELECT (ts / ?) * ? AS b, {cols} FROM samples "
            f"WHERE ts >= ? GROUP BY b ORDER BY b",
            (bucket, bucket, since),
        ).fetchall()
    except sqlite3.Error as err:
        return {"available": False, "reason": str(err)[:120]}
    finally:
        conn.close()

    points = []
    for row in rows:
        point = {"t": row[0]}
        for i, metric in enumerate(HISTORY_METRICS, start=1):
            value = row[i]
            point[metric] = round(value, 2) if isinstance(value, float) else value
        points.append(point)
    return {"available": True, "hours": hours, "bucket_seconds": bucket,
            "points": points}


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
    g["clocks"] = gpu_clocks()
    act = activity()
    pw = power()
    pm = power_meter()
    tc = transcribe_cost(pm.get("thb_per_kwh", 0) if pm.get("available") else 0)
    queue["current"] = act.get("current_job")
    # Long-running services + the alerting/protection safety-net (so a dead
    # watchdog/heartbeat is VISIBLE). Oneshots (fan-curve/battery-cap/...) are
    # excluded on purpose: they exit after applying, so is-active would false-red.
    services = [
        {"name": "transcribe-queue", "active": svc_active("transcribe-queue.service", user=True)},
        {"name": "watchdog", "active": svc_active("health-watchdog.timer", user=True)},
        {"name": "heartbeat", "active": svc_active("heartbeat.timer", user=True)},
        # netdata was purged 2026-08-06; power-meter is what feeds the cost
        # figures now, so a dead sampler is what actually needs to be visible.
        {"name": "power-meter", "active": svc_active("power-meter")},
        {"name": "tailscaled", "active": svc_active("tailscaled")},
        {"name": "firewall", "active": svc_active("ufw")},
        {"name": "fail2ban", "active": svc_active("fail2ban")},
    ]
    fails = failed_units()
    alerts = []
    if fails:
        alerts.append({"level": "crit", "msg": failed_units_msg(fails)})
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
            "cpu_pct": cpu_pct(), "cpu_temp": cpu_temp(), "fans": fans(),
            "load": [float(x) for x in open("/proc/loadavg").read().split()[:3]],
            "ram": r, "disk": disk, "gpu": g, "power": pw, "activity": act,
            "power_meter": pm, "transcribe_cost": tc,
            "tailscale": {"status": "connected" if ts_ok else "down", "ip": ts_ip},
            # failed_units stays an INT so any existing scraper keeps working;
            # the names are additive.
            "queue": queue, "services": services, "failed_units": len(fails),
            "failed_unit_names": fails, "alerts": alerts}


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
    """Cached status. A failing collector degrades the page, never kills it.

    Hardened 2026-08-07: an exception anywhere in build_status() used to
    propagate out of the request handler, so /status.json returned nothing and
    the UI showed SERVER OFFLINE even though the box was perfectly healthy.
    Serve the last good snapshot instead, flagged stale.
    """
    now = time.time()
    with _status_lock:
        if not _status_cache["data"] or now - _status_cache["ts"] > STATUS_TTL:
            try:
                _status_cache["data"] = build_status()
                _status_cache["ts"] = now
            except Exception as err:  # noqa: BLE001 - degrade, never 500
                stale = dict(_status_cache["data"] or {})
                stale["collector_error"] = f"{type(err).__name__}: {err}"[:200]
                stale.setdefault("alerts", []).append(
                    {"level": "warn", "msg": "collector error, showing last good data"})
                stale["stale"] = True
                _status_cache["data"] = stale
                _status_cache["ts"] = now
        data = _status_cache["data"]
    return _redact_public(data) if public else data


# ----- command console (privileged) ----------------------------------------
# /command runs `claude -p --dangerously-skip-permissions` as this user, who
# holds NOPASSWD sudo. Treat it as remote root. The token is the primary gate;
# these are the network gates behind it.
ALLOW_LAN_COMMAND = False       # set True to re-permit plain-LAN command posts
FUNNEL_HEADER = "Tailscale-Funnel-Request"


def _command_source_ok(client_ip, headers):
    """Whether a /command POST may proceed, as (ok, reason).

    Funnel traffic is checked by HEADER, not address: tailscaled proxies it
    from 127.0.0.1, so a public request would otherwise look like localhost.
    """
    if headers.get(FUNNEL_HEADER):
        return False, "tailscale funnel (public)"
    if client_ip.startswith("127.") or client_ip == "::1":
        return True, "localhost"
    if client_ip.startswith("100."):        # tailnet CGNAT 100.64.0.0/10
        try:
            second = int(client_ip.split(".")[1])
        except (IndexError, ValueError):
            return False, "malformed address"
        if 64 <= second <= 127:
            return True, "tailnet"
    if ALLOW_LAN_COMMAND:
        return True, "lan (explicitly allowed)"
    return False, "off-tailnet source"


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
        if path == "/asr":
            # Thai ASR model evaluation report (static)
            return self._file("asr.html", "text/html; charset=utf-8")
        if path == "/asr-live":
            return self._file("asr_live.html", "text/html; charset=utf-8")
        if path == "/now":
            return self._file("now.html", "text/html; charset=utf-8")
        if path == "/now.json":
            try:
                import now_running
                return self._send(200, "application/json",
                                  json.dumps(now_running.status()))
            except Exception as err:  # noqa: BLE001 - never 500 the dashboard
                return self._send(200, "application/json",
                                  json.dumps({"hostname": "leaddneung",
                                              "jobs": [], "queue": {},
                                              "vitals": {},
                                              "alerts": [{"level": "crit",
                                                          "text": str(err)[:80]}]}))
        if path == "/asr-job.json":
            try:
                import asr_job
                return self._send(200, "application/json",
                                  json.dumps(asr_job.status()))
            except Exception as err:  # noqa: BLE001 - never 500 the dashboard
                return self._send(200, "application/json",
                                  json.dumps({"state": "stopped", "pid": None,
                                              "phase": "error", "phase_index": 0,
                                              "phases": [], "elapsed_secs": None,
                                              "total_eta_secs": 0,
                                              "remaining_secs": None,
                                              "progress_pct": 0, "results": [],
                                              "log_tail": [str(err)], "gpu": None}))
        if path == "/runbook":
            # runbook.html shipped without a route; wire it up
            return self._file("runbook.html", "text/html; charset=utf-8")
        if path == "/history.json":
            hours = 24
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            for part in query.split("&"):
                key, _, value = part.partition("=")
                if key == "hours":
                    try:
                        hours = int(value)
                    except ValueError:
                        pass
            return self._send(200, "application/json",
                              json.dumps(history_series(hours)))
        if path == "/status.json":
            return self._send(200, "application/json", json.dumps(get_status(public=False)))
        if path == "/status.pub.json":
            # redacted feed for the shared /monitor view (no job filenames)
            return self._send(200, "application/json", json.dumps(get_status(public=True)))
        self.send_error(404)

    def do_POST(self):
        if self.path.split("?")[0] != "/command":
            return self.send_error(404)
        ok, why = _command_source_ok(self.client_address[0], self.headers)
        if not ok:
            _audit(self.client_address[0], "", f"blocked-source ({why})")
            return self._send(403, "application/json",
                              json.dumps({"error": "forbidden"}))
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
