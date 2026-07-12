#!/bin/bash
# Emergency health watchdog for leaddneung. Pushes to ntfy on problems.
# Flap-guard: only re-alerts for a condition every 30 min (state in /tmp).
# User services are auto-restarted before alerting (belt over Restart=always).
NTFY="https://ntfy.sh/YOUR_NTFY_TOPIC"
STATE=/tmp/health-state; mkdir -p $STATE
alert(){ # key, priority, title, body
  local key="$1" prio="$2" title="$3" body="$4"
  local last=$(cat "$STATE/$key" 2>/dev/null || echo 0)
  local now=$(date +%s)
  if [ $((now-last)) -ge 1800 ]; then
    curl -s -H "Title: $title" -H "Priority: $prio" -H "Tags: warning" -d "$body" "$NTFY" >/dev/null 2>&1
    echo $now > "$STATE/$key"
  fi
}
clear_state(){ rm -f "$STATE/$1"; }

# disk
D=$(df / | awk 'NR==2{print $5}' | tr -d '%'); [ "$D" -ge 90 ] && alert disk high "leaddneung: disk ${D}%" "Root filesystem at ${D}%." || clear_state disk
# mem
M=$(free | awk '/Mem:/{printf "%d", $3/$2*100}'); [ "$M" -ge 92 ] && alert mem high "leaddneung: RAM ${M}%" "Memory at ${M}%." || clear_state mem
# gpu temp
T=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits 2>/dev/null | head -1); [ -n "$T" ] && [ "$T" -ge 90 ] && alert gputemp urgent "leaddneung: GPU ${T}C" "GPU temperature ${T}C." || clear_state gputemp

# USER services: try to auto-restart, then alert with the outcome
for s in transcribe-queue.service dashboard.service; do
  if systemctl --user is-active --quiet "$s" 2>/dev/null; then
    clear_state "svc_$s"
  else
    systemctl --user restart "$s" 2>/dev/null; sleep 3
    if systemctl --user is-active --quiet "$s" 2>/dev/null; then
      alert "svc_$s" default "leaddneung: $s auto-recovered" "$s was down; watchdog restarted it successfully."
      clear_state "svc_$s"
    else
      alert "svc_$s" urgent "leaddneung: $s DOWN" "$s is down and auto-restart FAILED. Manual attention needed."
    fi
  fi
done

# SYSTEM services: can't restart without sudo -> alert only (they carry their own Restart=)
for s in netdata tailscaled; do
  systemctl is-active --quiet "$s" 2>/dev/null && clear_state "svc_$s" || alert "svc_$s" high "leaddneung: $s down" "System service $s not active."
done

# tailscale link
tailscale status >/dev/null 2>&1 && clear_state ts || alert ts urgent "leaddneung: tailscale down" "Tailscale not connected."

# ANY systemd unit in failed state (generic net beyond the named checks above)
FAILED=$(( $(systemctl --failed --no-legend --plain 2>/dev/null | grep -c .) + $(systemctl --user --failed --no-legend --plain 2>/dev/null | grep -c .) ))
if [ "$FAILED" -gt 0 ]; then
  alert failedunits high "leaddneung: ${FAILED} unit(s) failed" "${FAILED} systemd unit(s) entered failed state — run: systemctl --failed"
else
  clear_state failedunits
fi
