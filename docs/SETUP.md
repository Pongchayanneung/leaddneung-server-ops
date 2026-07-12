# Setup

Deploy the ops stack on a headless Ubuntu box that is reachable over Tailscale.
Commands assume the login user is `neung`; adjust paths to your own user.

## 0. Prerequisites

- Ubuntu 22.04/24.04, a login user with `sudo`.
- [Tailscale](https://tailscale.com) installed and up (`tailscale up`), MagicDNS on.
- An [ntfy](https://ntfy.sh) topic — just pick a long random name, e.g.
  `myserver-alerts-<8 random hex>`. Anyone who knows it can read/post, so treat
  it like a secret. Put it in `config.sh` (see `config.example.sh`).
- Headless persistence so `--user` services run without a login session:
  ```bash
  sudo loginctl enable-linger "$USER"
  ```

## 1. Dashboard + command console

```bash
mkdir -p ~/dashboard
cp dashboard/dashboard_server.py dashboard/index.html dashboard/console.html ~/dashboard/
# create the console secret (owner-only; 600)
head -c 24 /dev/urandom | base64 | tr -d '/+=' > ~/dashboard/.command_secret
chmod 600 ~/dashboard/.command_secret
touch ~/dashboard/COMMAND_ENABLED           # remove this file = kill switch
cp systemd/dashboard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now dashboard.service
```

Open `http://<your-tailnet-ip>:8080`. Share `…:8080/monitor` (read-only) with a
collaborator. Retrieve the console token with
`cat ~/dashboard/.command_secret`.

> The console runs `claude -p` on the server. If you don't want that, delete the
> `COMMAND_ENABLED` file (or the `/command` handler) — the read-only dashboard
> still works.

## 2. Alerts, heartbeat, watchdog

Edit the `NTFY=` line at the top of each script to your topic, then:

```bash
mkdir -p ~/transcribe-opt
cp scripts/health-watchdog.sh scripts/heartbeat.sh ~/transcribe-opt/
chmod +x ~/transcribe-opt/*.sh
cp systemd/health-watchdog.* systemd/heartbeat.* ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now health-watchdog.timer heartbeat.timer
```

Subscribe your phone's ntfy app to your topic. Fire a test:
`~/transcribe-opt/heartbeat.sh`.

## 3. Collaborator monitoring (optional, shared box)

Real-time push when a non-owner account logs in via SSH + a daily activity report.

```bash
sudo install -m755 scripts/ssh-login-notify.sh scripts/friend-report.sh /usr/local/bin/
# edit NTFY= in both, and set the owner username to skip in ssh-login-notify.sh
echo 'session optional pam_exec.so /usr/local/bin/ssh-login-notify.sh' | sudo tee -a /etc/pam.d/sshd
sudo cp systemd/friend-report.* /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now friend-report.timer
```

`pam_exec` is `optional`, so a script error can never lock you out of SSH — but
test a fresh login anyway.

## 4. Always-on + protection (system units)

```bash
sudo cp systemd/{battery-cap,gpu-persist,cpu-perf,tailscale-watchdog}.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now battery-cap gpu-persist cpu-perf tailscale-watchdog.timer
# never sleep
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
# firewall: tailnet-only
sudo ufw --force reset
sudo ufw default deny incoming && sudo ufw default allow outgoing
sudo ufw allow in on tailscale0 && sudo ufw allow in on lo
sudo ufw enable
sudo apt install -y fail2ban unattended-upgrades
```

## 5. Fan curve (ASUS ROG only)

```bash
sudo install -m755 scripts/fan-curve.sh /usr/local/bin/
sudo cp systemd/fan-curve.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now fan-curve
```

Confirm the hwmon path in `fan-curve.sh` matches your board
(`grep . /sys/class/hwmon/hwmon*/name`).

## Verify

```bash
systemctl --user list-timers            # heartbeat + watchdog scheduled
curl -s localhost:8080/status.json | head
systemctl --failed                      # should be empty
```
