# Commands Reference

## Service Control

```bash
sudo systemctl start psiphon-tun       # Start VPN
sudo systemctl stop psiphon-tun        # Stop VPN
sudo systemctl status psiphon-tun      # Check status
sudo systemctl restart psiphon-tun     # Full restart (slow)
sudo systemctl reload psiphon-tun      # Reload config (preferred)
sudo systemctl enable psiphon-tun      # Auto-start on boot
sudo systemctl disable psiphon-tun     # Don't auto-start
```

## Testing

```bash
# Connection test
curl --interface PsiphonTUN https://ifconfig.me

# DNS test
dig @8.8.8.8 google.com

# Kill switch test (should fail)
timeout 5 curl https://ifconfig.me
```

## Monitoring

```bash
# Quick status
sudo systemctl status psiphon-tun

# Live logs
sudo journalctl -u psiphon-tun -f

# Last 50 log lines
sudo journalctl -u psiphon-tun -n 50

# Psiphon process logs
sudo tail -f /opt/psiphon-tun/psiphon-core.log
```

## Diagnostics

```bash
# Full diagnostics
sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose

# Status check
sudo ./Psiphon-Linux-VPN-Service-Setup.sh status

# Help
sudo ./Psiphon-Linux-VPN-Service-Setup.sh help
```

## Configuration

```bash
# Edit config
sudo nano /opt/psiphon-tun/psiphon/psiphon.config

# Validate JSON
jq . /opt/psiphon-tun/psiphon/psiphon.config

# Backup config
sudo cp /opt/psiphon-tun/psiphon/psiphon.config \
        ~/psiphon.config.backup

# Reload after edit
sudo systemctl reload psiphon-tun
```

## Verification

```bash
# Process running?
pgrep -f psiphon-tunnel-core

# TUN interface UP?
ip addr show PsiphonTUN

# Kill switch active?
sudo nft list chain inet psiphon_filter output | head -1

# Routes configured?
ip route | grep PsiphonTUN

# DNS configured?
cat /etc/resolv.conf
```

## System Check

```bash
# All at once
echo "Service:" && sudo systemctl is-active psiphon-tun && \
echo "Process:" && pgrep -f psiphon-tunnel-core && \
echo "TUN:" && ip addr show PsiphonTUN >/dev/null && echo "UP" && \
echo "Internet:" && curl -s --interface PsiphonTUN ifconfig.me
```

---

See [Usage & Commands](USAGE.md) for detailed explanations.
