# Copy to config.sh and fill in. config.sh is gitignored — never commit real values.
#
# ntfy topic: a capability secret. Anyone who knows it can READ all your alerts
# and POST fake ones to your phone. Pick a long random name and keep it private.
#   e.g.  myserver-alerts-$(head -c4 /dev/urandom | xxd -p)
export NTFY_TOPIC="YOUR_NTFY_TOPIC"

# Your machine's Tailscale IP (100.x.y.z) or MagicDNS name.
export TAILSCALE_IP="YOUR_TAILSCALE_IP"

# Login user that OWNS the box (skipped by the SSH-login alerter to avoid self-spam).
export OWNER_USER="neung"

# Optional: non-owner account name to monitor on a shared box.
export COLLAB_USER="collab"
