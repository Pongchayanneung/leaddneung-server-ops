#!/bin/bash
# SSH login monitor for the shared collab (a collaborator) account.
# Wired via PAM in /etc/pam.d/sshd. Handles open + close sessions.
[ "$PAM_SERVICE" = "sshd" ] || exit 0
[ "$PAM_USER" = "neung" ] && exit 0        # skip owner, no self-spam
LOG=/var/log/collab-access.log
TS=$(date "+%Y-%m-%d %H:%M:%S %z")
NTFY="https://ntfy.sh/YOUR_NTFY_TOPIC"
case "$PAM_TYPE" in
  open_session)
    echo "$TS  LOGIN   user=$PAM_USER from=${PAM_RHOST:-local} tty=${PAM_TTY:-?}" >> "$LOG"
    curl -s -H "Title: SSH login: $PAM_USER" -H "Priority: high" -H "Tags: eyes"       -d "$PAM_USER เข้าใช้เซิร์ฟเวอร์ผ่าน ssh จาก ${PAM_RHOST:-unknown} เวลา $(date "+%H:%M %d/%m")"       "$NTFY" >/dev/null 2>&1 &
    ;;
  close_session)
    echo "$TS  LOGOUT  user=$PAM_USER from=${PAM_RHOST:-local} tty=${PAM_TTY:-?}" >> "$LOG"
    ;;
esac
exit 0
