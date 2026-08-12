#!/bin/bash
# Emergency health watchdog for leaddneung. Pushes to ntfy on problems.
# Flap-guard: only re-alerts for a condition every 30 min (state in /tmp).
# User services are auto-restarted before alerting (belt over Restart=always).
# WHY THE URL IS NOT INLINE (do not paste it back):
# An ntfy topic URL is a bearer capability, not an address. Anyone who can read this
# string can read every alert this box sends AND post convincing fakes to it. This
# script is world-readable and neung/tong/collab are all in the sudo group here, so the
# URL lives in ~/.config/leaddneung/ntfy.url (mode 600) and is read at run time. Same
# convention as ~/bin/offsite-backup.sh, which already sources it this way.
NTFY_FILE="$HOME/.config/leaddneung/ntfy.url"
NTFY=$([ -r "$NTFY_FILE" ] && cat "$NTFY_FILE")
# ROTATION TRANSITION: while ntfy.url.old exists, every alert goes to BOTH topics, so a
# phone still subscribed to the old one keeps receiving. Swapping the topic outright would
# leave that phone silently receiving nothing, which is the exact failure this box's
# alerting exists to prevent. TO FINISH THE ROTATION, DELETE ~/.config/leaddneung/ntfy.url.old
# -- that is all it takes, no code change here.
NTFY_OLD_FILE="$NTFY_FILE.old"
NTFY_OLD=$([ -r "$NTFY_OLD_FILE" ] && cat "$NTFY_OLD_FILE")

# A watchdog that cannot alert is BLIND, and that is exactly the class of failure it
# exists to catch, so a missing config file must never be a silent no-op. offsite-backup.sh
# returns silently in this case; here it gets three traces instead: this line every run,
# the full text of each suppressed alert below, and a non-zero exit at the bottom so the
# unit shows up in `systemctl --user --failed`. One line per run is bounded, not spam.
[ -n "$NTFY" ] || echo "health-watchdog: NO ntfy URL at $NTFY_FILE - this run CANNOT alert" >&2
STATE=/tmp/health-state; mkdir -p $STATE
alert(){ # key, priority, title, body   -- fixed 30 min flap guard
  alert_every 1800 "$@"
}

# Same as alert() but with a caller-chosen minimum gap. Exists because a fixed
# interval is wrong for a condition that persists: offsite-backup, blocked on a B2
# key only a human can create, sent 22 of this box's 24 alerts in one day, one every
# 31 minutes. Every one of them was TRUE, which is what makes it dangerous. A channel
# that cries the same true thing 46 times a day gets muted, and then the next real
# alert lands in a muted channel. Repeat rate has to decay as a fault ages.
alert_every(){ # interval, key, priority, title, body
  local interval="$1" key="$2" prio="$3" title="$4" body="$5"
  local last=$(cat "$STATE/$key" 2>/dev/null || echo 0)
  local now=$(date +%s)
  if [ $((now-last)) -ge "$interval" ]; then
    # No URL: emit the alert to stderr (systemd captures it -> journalctl --user -u
    # health-watchdog) and deliberately DO NOT write the flap-guard state, so the alert
    # fires for real on the first run after the config file comes back.
    if [ -z "$NTFY" ]; then
      echo "health-watchdog: alert NOT SENT (no ntfy URL) [$prio] $title | $body" >&2
      return 0
    fi
    local u
    for u in "$NTFY" ${NTFY_OLD:+"$NTFY_OLD"}; do
      curl -s -H "Title: $title" -H "Priority: $prio" -H "Tags: warning" -d "$body" "$u" >/dev/null 2>&1
    done
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
for s in transcribe-queue.service dashboard.service tg-bot.service; do
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

# SYSTEM services: cannot restart without sudo -> alert only (they carry their own Restart=)
# netdata REMOVED 2026-08-08: it was purged on 2026-08-06, so this loop pushed a
# false "netdata down" alert every 30 min for two days. A false alarm trains you
# to ignore the channel. Do not re-add a service that is not installed.
for s in tailscaled; do
  systemctl is-active --quiet "$s" 2>/dev/null && clear_state "svc_$s" || alert "svc_$s" high "leaddneung: $s down" "System service $s not active."
done

# tailscale link
tailscale status >/dev/null 2>&1 && clear_state ts || alert ts urgent "leaddneung: tailscale down" "Tailscale not connected."

# ANY systemd unit in failed state (generic net beyond the named checks above)
#
# Keyed PER UNIT, not by a single "failedunits" key. The old version alerted on a
# count under one shared key, which broke twice over:
#   1. A NEW failure arriving while an old one was still failed hit the same 30-min
#      flap-guard and got swallowed. offsite-backup sat failed for days, so anything
#      that broke after it was invisible until the guard happened to expire.
#   2. "2 unit(s) failed" never said WHICH, so 48 pings a day were unactionable and
#      the only rational response was to stop reading them.
# Per-unit keys mean a new failure always announces itself, and the unit is named.
now=$(date +%s)
declare -A still_failed=()

while read -r scope unit; do
  [ -n "$unit" ] || continue
  key="fail_${scope}_${unit}"
  still_failed[$key]=1

  # Age = the EARLIEST evidence of the fault, from two sources that fail differently.
  # systemd's StateChangeTimestamp survives a state-dir wipe but is rewritten by every
  # retry, so a timer-driven unit resets to "0h" on each attempt: offsite-backup showed
  # "19h" at 04:49 and "0h" at 05:21 after its 05:04 retry, and could therefore never
  # reach the 24h escalation no matter how long it stayed broken. A local first-seen
  # file has the opposite flaw, resetting on reboot. Taking the older of the two is
  # correct under both, and only ever understates the age if BOTH were lost.
  FIRST=$STATE/firstfail; mkdir -p "$FIRST"
  [ -f "$FIRST/$key" ] || echo "$now" > "$FIRST/$key"
  seen_epoch=$(cat "$FIRST/$key" 2>/dev/null || echo "$now")
  changed=$(systemctl ${scope:+--$scope} show "$unit" -p StateChangeTimestamp --value 2>/dev/null)
  changed_epoch=$(date -d "$changed" +%s 2>/dev/null || echo "$now")
  [ "$seen_epoch" -lt "$changed_epoch" ] && changed_epoch=$seen_epoch
  age_h=$(( (now - changed_epoch) / 3600 ))

  # A unit broken for a day is a different problem from one that just broke: the
  # first needs you, the second might still self-recover. Escalate on age so a
  # long-running breakage cannot fade into the background at default priority.
  #
  # The REPEAT RATE decays as the same fault ages, while priority rises. A fresh
  # failure is news and is worth interrupting you for; a fault you have known about
  # for a day is a reminder, and reminding someone every 31 minutes is how a channel
  # gets muted. Fast when it is news, rare when it is a standing item, never silent.
  if   [ "$age_h" -ge 24 ]; then prio=urgent; iv=43200   # >1 day  -> twice a day
  elif [ "$age_h" -ge 12 ]; then prio=high;   iv=21600   # >12h    -> every 6h
  elif [ "$age_h" -ge 2  ]; then prio=high;   iv=7200    # >2h     -> every 2h
  else                           prio=high;   iv=1800    # fresh   -> every 30 min
  fi
  age_txt="failing for ${age_h}h"

  detail=$(systemctl ${scope:+--$scope} status "$unit" --no-pager 2>/dev/null \
           | grep -iE "^ *(Process|Main PID|Active):" | head -3 | sed 's/^ *//')
  alert_every "$iv" "$key" "$prio" "leaddneung: $unit failed" \
        "$unit ($scope) is in failed state, ${age_txt}.
$detail
Inspect: systemctl ${scope:+--$scope} status $unit"
done < <(
  systemctl        --failed --no-legend --plain 2>/dev/null | awk '{print "system", $1}'
  systemctl --user --failed --no-legend --plain 2>/dev/null | awk '{print "user",   $1}'
)

# Drop the flap-guard for units that recovered, so the NEXT time one breaks it
# alerts at once instead of sitting out the remainder of a 30-min window opened by
# the previous outage.
for f in "$STATE"/fail_*; do
  [ -e "$f" ] || continue
  k=$(basename "$f")
  # The first-seen stamp must go too. Leaving it behind would make a unit that broke,
  # recovered, and broke again inherit the OLD age: it would open at "36h", jump
  # straight to the twice-a-day rate, and so report a brand new fault both as ancient
  # and as barely worth mentioning.
  [ -n "${still_failed[$k]:-}" ] || { clear_state "$k"; rm -f "$STATE/firstfail/$k"; }
done

# Fail the unit when alerting is unconfigured, so being blind is visible in
# `systemctl --user --failed` even on a run where nothing was wrong to report.
[ -n "$NTFY" ] || exit 1
exit 0
