#!/bin/bash
# Proof-of-life heartbeat for leaddneung. Pushes a healthy summary to ntfy
# twice daily. If a heartbeat is MISSING, the server or its network is dead
# (a passive dead-man switch that internal alerts can't provide).
# WHY THE URL IS NOT INLINE (do not paste it back):
# An ntfy topic URL is a bearer capability, not an address. Anyone who can read this
# string can read every alert this box sends AND post convincing fakes to it. This
# script is world-readable and neung/tong/collab are all in the sudo group here, so the
# URL lives in ~/.config/leaddneung/ntfy.url (mode 600) and is read at run time. Same
# convention as ~/bin/offsite-backup.sh, which already sources it this way.
NTFY_FILE="$HOME/.config/leaddneung/ntfy.url"
NTFY=$([ -r "$NTFY_FILE" ] && cat "$NTFY_FILE")

up=$(uptime -p 2>/dev/null | sed 's/^up //')
disk=$(df / | awk 'NR==2{print $5}')
mem=$(free | awk '/Mem:/{printf "%d%%", $3/$2*100}')
read gtemp gutil < <(nvidia-smi --query-gpu=temperature.gpu,utilization.gpu --format=csv,noheader,nounits 2>/dev/null | head -1 | tr ',' ' ')
q=$(python3 - <<'PY' 2>/dev/null || echo "n/a"
import json, os
d = json.load(open(os.path.expanduser("~/transcribe-queue/status.json")))
print(f"{d.get('pending',0)}p/{d.get('done',0)}done")
PY
)

bad=""
for s in transcribe-queue.service dashboard.service tg-bot.service stt-gateway.service; do
  systemctl --user is-active --quiet "$s" 2>/dev/null || bad="$bad ${s%.service}"
done
# netdata REMOVED 2026-08-11: it was purged on 2026-08-06, so this loop appended a
# phantom "DOWN: netdata" to EVERY heartbeat for five days. health-watchdog.sh was
# given this same fix on 2026-08-08; heartbeat.sh was missed, which is why the bug
# survived here. Do not re-add a service that is not installed.
#
# This is worse than the watchdog version was. A heartbeat is a dead-man switch, so
# its whole value is that "all services up" means something. Once every message says
# DOWN, a real outage can only ADD a name to a line already reading DOWN, and the
# signal is gone. Anything listed here must be verified installed before it is added.
for s in tailscaled; do
  systemctl is-active --quiet "$s" 2>/dev/null || bad="$bad $s"
done

if [ -z "$bad" ]; then status="all services up"; tag="white_check_mark"; else status="DOWN:$bad"; tag="warning"; fi
body="up ${up:-?} | disk ${disk} | RAM ${mem} | GPU ${gtemp:-?}C/${gutil:-?}% | queue ${q} | ${status}"
# A heartbeat that cannot be sent looks identical, from outside, to a dead server, so it
# has to leave the trace locally instead. stderr goes to the journal (journalctl --user -u
# heartbeat) and exit 1 puts the unit in `systemctl --user --failed`, which health-watchdog's
# failed-unit sweep then reports. Exiting 0 quietly would be the worst outcome: the dead-man
# switch would look armed while sending nothing.
if [ -z "$NTFY" ]; then
  echo "heartbeat: NOT SENT (no ntfy URL at $NTFY_FILE) | ${body}" >&2
  exit 1
fi
curl -s -H "Title: leaddneung alive" -H "Priority: low" -H "Tags: ${tag}" -d "${body}" "$NTFY" >/dev/null 2>&1
