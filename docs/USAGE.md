# Usage & Commands

## Starting & Stopping

```bash
# Start (keeps kill switch inactive during startup)
sudo systemctl start psiphon-tun

# Stop (activates kill switch - blocks all traffic)
sudo systemctl stop psiphon-tun

# Check status
sudo systemctl status psiphon-tun
```

## Reloading vs Restarting

```bash
# RELOAD (preferred) - keeps kill switch, just restarts Psiphon
sudo systemctl reload psiphon-tun
# Use when: Config changed, need reconnect, want quick restart

# RESTART (slower) - full network rebuild
sudo systemctl restart psiphon-tun
# Use when: reload doesn't work, major issues
```

## Monitoring

### Live Status
```bash
watch -n 2 'sudo systemctl status psiphon-tun'
```

### Real-Time Logs
```bash
# Systemd logs
sudo journalctl -u psiphon-tun -f

# Psiphon process logs
sudo tail -f /opt/psiphon-tun/psiphon-core.log

# Both in one terminal
sudo journalctl -u psiphon-tun -u psiphon-binary -f
```

### View Recent Logs
```bash
sudo journalctl -u psiphon-tun -n 50     # Last 50 lines
sudo journalctl -u psiphon-tun -n 100    # Last 100 lines
sudo journalctl -u psiphon-tun --since '10 minutes ago'
```

## Testing Connectivity

```bash
# Quick test
curl --interface PsiphonTUN https://ifconfig.me

# Shows IP? Connected.
# No response? Check TROUBLESHOOTING.md

# DNS test
dig @8.8.8.8 google.com

# IPv6 test
curl --interface PsiphonTUN -6 https://ifconfig.me
```

## SOCKS Proxy Usage

Psiphon provides a SOCKS5 proxy on port 1081.

### curl
```bash
curl --socks5 127.0.0.1:1081 https://example.com
```

### Firefox
Settings → Network → Proxy:
- SOCKS Host: 127.0.0.1
- SOCKS Port: 1081
- SOCKS v5

### Chrome
```bash
google-chrome --proxy-server="socks5://127.0.0.1:1081"
```

### Tor Browser
Settings → Connection → SOCKS 5: 127.0.0.1:1081

## HTTP Proxy Usage

Port 8081 provides an HTTP proxy:

```bash
# curl
curl -x http://127.0.0.1:8081 https://example.com

# Firefox
Settings → Network → Proxy:
- HTTP Proxy: 127.0.0.1
- Port: 8081
```

## Auto-Start on Boot

```bash
# Enable
sudo systemctl enable psiphon-tun

# Disable
sudo systemctl disable psiphon-tun

# Check if enabled
sudo systemctl is-enabled psiphon-tun
```

## Common Operations

```bash
# Change region (then reload)
sudo nano /opt/psiphon-tun/psiphon/psiphon.config
# Edit "EgressRegion": "US"  (or CA, GB, AU, etc.)
sudo systemctl reload psiphon-tun

# Verify kill switch is active
sudo nft list chain inet psiphon_filter output | head -1
# Should show: policy drop

# Check TUN interface
ip addr show PsiphonTUN

# Check routes
ip route | grep PsiphonTUN

# See all active connections
ss -tunap | grep psiphon
```

## Install & Uninstall

```bash
# Install
sudo ./Psiphon-Linux-VPN-Service-Setup.sh install

# Uninstall (removes everything)
sudo ./Psiphon-Linux-VPN-Service-Setup.sh uninstall

# Reinstall fresh
sudo ./Psiphon-Linux-VPN-Service-Setup.sh uninstall
sudo ./Psiphon-Linux-VPN-Service-Setup.sh install
```

---

For more: [Commands Reference](COMMANDS.md) | [Troubleshooting](TROUBLESHOOTING.md)
