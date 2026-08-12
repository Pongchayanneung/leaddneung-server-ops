#!/bin/bash
# SSH login monitor for the shared collab (a collaborator) account.
# Wired via PAM in /etc/pam.d/sshd. Handles open + close sessions.
[ "$PAM_SERVICE" = "sshd" ] || exit 0
[ "$PAM_USER" = "neung" ] && exit 0        # skip owner, no self-spam
LOG=/var/log/collab-access.log
TS=$(date "+%Y-%m-%d %H:%M:%S %z")
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
case "$PAM_TYPE" in
  open_session)
    echo "$TS  LOGIN   user=$PAM_USER from=${PAM_RHOST:-local} tty=${PAM_TTY:-?}" >> "$LOG"
    if [ -z "$NTFY" ]; then
      echo "$TS  ALERT-NOT-SENT  no ntfy URL at $NTFY_FILE user=$PAM_USER" >> "$LOG"
      logger -t ssh-login-notify "NOT SENT: no ntfy URL at $NTFY_FILE (user=$PAM_USER)"
    else
      for u in "$NTFY" ${NTFY_OLD:+"$NTFY_OLD"}; do
        curl -s -H "Title: SSH login: $PAM_USER" -H "Priority: high" -H "Tags: eyes"       -d "$PAM_USER เข้าใช้เซิร์ฟเวอร์ผ่าน ssh จาก ${PAM_RHOST:-unknown} เวลา $(date "+%H:%M %d/%m")"       "$u" >/dev/null 2>&1 &
      done
    fi
    ;;
  close_session)
    echo "$TS  LOGOUT  user=$PAM_USER from=${PAM_RHOST:-local} tty=${PAM_TTY:-?}" >> "$LOG"
    ;;
esac
exit 0
