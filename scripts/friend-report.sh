#!/bin/bash
# Daily activity report for the shared 'collab' friend account. Runs as root
# (systemd system timer) so it can read /home/collab and process accounting.
U=collab
# WHY THE URL IS NOT INLINE (do not paste it back):
# An ntfy topic URL is a bearer capability, not an address: anyone who can read the string
# can read every alert this box sends AND post convincing fakes to it. This file is readable
# by others and neung/tong/collab are all in the sudo group, so the topic sat here in
# cleartext until it was rotated on 2026-08-12. It is now read at run time from a mode-600
# file, the same convention as ~neung/transcribe-opt/health-watchdog.sh.
#
# ROTATION TRANSITION: while ntfy.url.old exists, every message is sent to BOTH topics, so a
# phone still subscribed to the old topic keeps receiving during the changeover.
# TO FINISH THE ROTATION, DELETE /home/neung/.config/leaddneung/ntfy.url.old -- that is all
# it takes, no code change here.
NTFY_FILE="/home/neung/.config/leaddneung/ntfy.url"
NTFY_OLD_FILE="$NTFY_FILE.old"
NTFY=$([ -r "$NTFY_FILE" ] && cat "$NTFY_FILE")
NTFY_OLD=$([ -r "$NTFY_OLD_FILE" ] && cat "$NTFY_OLD_FILE")
now=$(date '+%H:%M %d/%m')

onl=$(who 2>/dev/null | grep -cw "$U")
sess=$(loginctl list-sessions --no-pager 2>/dev/null | awk -v u="$U" '$3==u' | wc -l)
today=$(last -F "$U" 2>/dev/null | grep -c "$(date '+%b %e')")
last3=$(last -aF "$U" 2>/dev/null | head -3 | tr -s ' ' | sed 's/^/    /')
nproc=$(ps -u "$U" --no-headers 2>/dev/null | wc -l)
cpu=$(ps -u "$U" --no-headers -o pcpu= 2>/dev/null | awk '{s+=$1} END{printf "%.0f", s+0}')
duh=$(du -sh "/home/$U" 2>/dev/null | cut -f1)

gpuc="ไม่"
gpuapps=$(nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null)
for pid in $(pgrep -u "$U" 2>/dev/null); do echo "$gpuapps" | grep -qw "$pid" && gpuc="ใช่"; done

cmds=""
if command -v lastcomm >/dev/null 2>&1; then
  cmds=$(lastcomm --user "$U" 2>/dev/null | head -8 | awk '{print "    "$1}' | sort -u | tr '\n' ' ')
fi

body="สรุปกิจกรรมเพื่อน (collab) $now
ออนไลน์ตอนนี้: $([ "$onl" -gt 0 ] && echo "ใช่ ($sess session)" || echo "ไม่")
ล็อกอินวันนี้: ${today} ครั้ง
โปรเซส: ${nproc} ตัว, CPU รวม ${cpu}%
ใช้ GPU: ${gpuc}
พื้นที่ /home/collab: ${duh:-?}
${cmds:+คำสั่งล่าสุด: $cmds
}ล็อกอินล่าสุด:
${last3:-    (ยังไม่มีบันทึก)}"

prio="low"; [ "$onl" -gt 0 ] && prio="default"
if [ -z "$NTFY" ]; then
  echo "friend-report: NOT SENT (no ntfy URL at $NTFY_FILE)" >&2
else
  for u in "$NTFY" ${NTFY_OLD:+"$NTFY_OLD"}; do
    curl -s -H "Title: กิจกรรมเพื่อน collab" -H "Priority: $prio" -H "Tags: eyes" -d "$body" "$u" >/dev/null 2>&1
  done
fi
echo "$body"
# blind alerting must fail the unit, not pass quietly
[ -n "$NTFY" ] || exit 1
