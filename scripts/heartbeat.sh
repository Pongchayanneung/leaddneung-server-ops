#!/bin/bash
# Proof-of-life heartbeat for leaddneung. Pushes a healthy summary to ntfy
# twice daily. If a heartbeat is MISSING, the server or its network is dead
# (a passive dead-man switch that internal alerts can't provide).
NTFY="https://ntfy.sh/YOUR_NTFY_TOPIC"

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
for s in transcribe-queue.service dashboard.service; do
  systemctl --user is-active --quiet "$s" 2>/dev/null || bad="$bad ${s%.service}"
done
for s in netdata tailscaled; do
  systemctl is-active --quiet "$s" 2>/dev/null || bad="$bad $s"
done

if [ -z "$bad" ]; then status="all services up"; tag="white_check_mark"; else status="DOWN:$bad"; tag="warning"; fi
body="up ${up:-?} | disk ${disk} | RAM ${mem} | GPU ${gtemp:-?}C/${gutil:-?}% | queue ${q} | ${status}"
curl -s -H "Title: leaddneung alive" -H "Priority: low" -H "Tags: ${tag}" -d "${body}" "$NTFY" >/dev/null 2>&1
