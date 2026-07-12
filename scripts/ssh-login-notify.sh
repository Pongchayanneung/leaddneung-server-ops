#!/bin/bash
# Real-time SSH login notifier. Monitors the shared 'collab' friend account.
# Wired via PAM (session open) in /etc/pam.d/sshd.
[ "$PAM_TYPE" = "open_session" ] || exit 0
[ "$PAM_SERVICE" = "sshd" ] || exit 0
[ "$PAM_USER" = "neung" ] && exit 0     # owner logins: skip (avoids self-spam)

NTFY="https://ntfy.sh/YOUR_NTFY_TOPIC"
curl -s -H "Title: SSH login: $PAM_USER" -H "Priority: high" -H "Tags: eyes" \
  -d "$PAM_USER เข้าใช้เซิร์ฟเวอร์ผ่าน ssh จาก ${PAM_RHOST:-unknown} เวลา $(date '+%H:%M %d/%m')" \
  "$NTFY" >/dev/null 2>&1 &
exit 0
