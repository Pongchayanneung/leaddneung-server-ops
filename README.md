# Connecting to leaddneung

This is a private dev server. Access is invite-only over Tailscale (no public internet exposure).

## 1. Install Tailscale

- macOS: https://tailscale.com/download/mac
- Windows: https://tailscale.com/download/windows
- Linux: `curl -fsSL https://tailscale.com/install.sh | sh`

## 2. Accept the shared-device invite

The server owner will send you a Tailscale sharing invite link (from the Tailscale admin console).
Open it and accept — this gives your device network access to just this one machine, not the owner's whole tailnet.

Run `tailscale up` and log in with your own account (Google/GitHub/Microsoft — whichever you used to sign up for Tailscale).

## 3. Generate an SSH key (if you don't already have one)

```
ssh-keygen -t ed25519 -C "your-name"
```

Send the contents of `~/.ssh/id_ed25519.pub` to the server owner — **never send the private key**.

## 4. First login

You'll be given a temporary username/password out-of-band (not in this repo). On first login you'll
be forced to set a new password immediately:

```
ssh <username>@<server-tailscale-ip>
```

## 5. Switch to key-only login

Once the owner has added your public key, password login for your account will be disabled and
you'll connect with just:

```
ssh <username>@<server-tailscale-ip>
```

No password needed at that point.
