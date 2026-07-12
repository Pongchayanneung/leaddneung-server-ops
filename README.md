# leaddneung-server-ops

A complete, self-hosted **operations stack for an always-on GPU workstation-as-server** — turn a laptop (here an ASUS ROG with an RTX 3070) into an unattended 24/7 node you can watch, get alerted about, and fix entirely from your phone.

Built for a headless Ubuntu box reachable over a [Tailscale](https://tailscale.com) tailnet. Everything is stdlib Python + bash + systemd — no agents, no cloud dashboard, no external dependencies to trust.

> This is a sanitized copy of a real running setup. Replace the placeholders
> (`YOUR_NTFY_TOPIC`, `YOUR_TAILSCALE_IP`) with your own before deploying.

---

## What you get

| Capability | How |
|---|---|
| **One-link live dashboard** | stdlib HTTP server → GPU/CPU/RAM/disk/services/queue/activity, auto-refresh, mobile-first |
| **Shareable read-only view** | `/monitor` route hides the command console + redacts job filenames — safe to hand a collaborator |
| **Phone push alerts** | [ntfy](https://ntfy.sh) on disk-full / RAM / GPU-temp / service-down / tailscale-down / **AC-unplugged** |
| **Proof-of-life heartbeat** | twice-daily "still alive" push; a *missing* heartbeat = server/network dead (passive dead-man) |
| **Self-healing** | `Restart=always` + a watchdog that restarts downed user services before alerting |
| **Remote fix from phone** | secret-gated command console runs `claude -p` on the box (kill-switch, rate-limit, audit log) |
| **Activity visibility** | who's logged in, per-user CPU/procs, GPU jobs, current transcription — on a shared box |
| **Collaborator login alerts** | real-time push when a non-owner account logs in via SSH (PAM hook) |
| **Thermal tuning** | ASUS 8-point custom fan curve (GPU 87°C → 66°C under load, silent at idle) |
| **Always-on hardening** | sleep masked, lid ignored, battery charge cap, governor pinned, tailscale watchdog |
| **Protection** | ufw (tailnet-only), fail2ban, unattended-upgrades, SSH key-only |

Optional companion: a faster-whisper transcription queue (drop audio in a folder, get `.txt`/`.srt` back).

---

## Architecture

```
   phone (Tailscale + ntfy app)
        │  http://YOUR_TAILSCALE_IP:8080         ntfy.sh/YOUR_NTFY_TOPIC
        ▼                                                ▲
┌───────────────────────── leaddneung (Ubuntu, RTX 3070) ────────────────────┐
│  dashboard_server.py  ──►  /  /monitor  /status.json  /console  /command    │
│  health-watchdog (3m)  ─────────────────────────────────────────────┐       │
│  heartbeat (08:00/20:00) ───────────────────────────────────────────┼──► ntfy
│  friend-report (20:00) + PAM ssh-login-notify ──────────────────────┘       │
│  systemd: fan-curve · battery-cap · gpu-persist · cpu-perf · ts-watchdog     │
│  ufw (tailnet-only) · fail2ban · SSH key-only                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Repo layout

```
dashboard/     dashboard_server.py  index.html  console.html
scripts/       health-watchdog.sh  heartbeat.sh  friend-report.sh
               ssh-login-notify.sh  fan-curve.sh
systemd/       *.service / *.timer for every unit above
docs/          runbook.html (phone cheat-sheet)  SETUP.md
config.example.sh   placeholders to fill in
```

---

## Quick start

1. Read **[docs/SETUP.md](docs/SETUP.md)**.
2. Copy `config.example.sh` → `config.sh`, fill in your ntfy topic + tailnet IP.
3. Drop the scripts in `~/`, install the systemd units, `systemctl enable --now` them.
4. Subscribe your phone's ntfy app to your topic; open `http://<your-tailnet-ip>:8080`.

---

## Security model

- **Network boundary is the tailnet.** `ufw` allows ingress only on `tailscale0` + `lo`; the LAN can't reach any port. The dashboard/console are visible only to tailnet members.
- **Control is secret-gated.** `POST /command` requires a token (`hmac.compare_digest`) stored server-side in a `600` file, plus a kill-switch flag, rate limit, concurrency lock, timeout, output redaction, and an audit log. The `/monitor` view hides the console link client-side, but the real gate is server-side — hiding a link never weakens it.
- **Sudo stays password-gated**, so the command console is naturally bounded to non-root actions.
- **Shared-view redaction.** `/monitor` serves a `/status.pub.json` feed that strips transcription filenames so a collaborator sees *that* a job runs, not *what*.
- **Never commit:** your ntfy topic (a capability secret — anyone with it can read/spam your alerts), `.command_secret`, tailnet IPs. See `.gitignore`.

---

## Notes

- Tuned for an ASUS ROG (`asus_custom_fan_curve`, ATK battery extension) but the monitoring/alerting layer is hardware-agnostic.
- ntfy topics are unauthenticated capability URLs — treat the topic name like a password and rotate it if it ever leaks.
- MIT-style: use it, adapt it, no warranty.
