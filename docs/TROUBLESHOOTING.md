# Troubleshooting

## Diagnose Problems

```bash
# Run first, every time
sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose

# Shows: interfaces, routes, firewall, processes, DNS, kill switch
```

## Common Issues

### Service Won't Start

**What you see:**
```
systemctl start psiphon-tun → fails or hangs
```

**Fix:**
```bash
# 1. Check what's wrong
sudo systemctl status psiphon-tun -l
sudo journalctl -u psiphon-tun -n 50

# 2. Common fixes
sudo systemctl restart psiphon-tun  # Try restart

# 3. Check if old process is stuck
sudo killall -9 psiphon-tunnel-core 2>/dev/null
sudo systemctl start psiphon-tun

# 4. Clean start
sudo rm -f /run/psiphon-tun.lock /run/psiphon-tun.pid
sudo systemctl start psiphon-tun
```

### No Internet After Starting

**What you see:**
```
Service running but curl --interface PsiphonTUN times out
```

**Fix:**
```bash
# 1. Wait - tunnel takes time
sleep 15
curl --interface PsiphonTUN https://ifconfig.me

# 2. Check logs
sudo tail -50 /opt/psiphon-tun/psiphon-core.log | grep -i "error\|tunnel"

# 3. Reload service
sudo systemctl reload psiphon-tun
sleep 10
curl --interface PsiphonTUN https://ifconfig.me

# 4. If still down, full restart
sudo systemctl restart psiphon-tun
sleep 15
curl --interface PsiphonTUN https://ifconfig.me

# 5. Try different region
sudo nano /opt/psiphon-tun/psiphon/psiphon.config
# Change "EgressRegion": "" → "US"
sudo systemctl reload psiphon-tun
```

### Intermittent Disconnections

**What you see:**
```
Connected 5-10 minutes, then drops
Frequent reconnects in logs
```

**Fix:**
```bash
# 1. Increase timeout
sudo nano /opt/psiphon-tun/psiphon/psiphon.config
# Change "EstablishTunnelTimeoutSeconds": 60 → 300

# 2. Single tunnel only
# Change "TunnelPoolSize": 2 → 1

sudo systemctl reload psiphon-tun
```

### Kill Switch Not Working

**What you see:**
```
Service stopped, can still reach internet
```

**Fix - CRITICAL:**
```bash
# Verify it's active
sudo nft list chain inet psiphon_filter output | head -1

# Should show: policy drop

# If not, restart
sudo systemctl restart psiphon-tun

# Verify again
sudo nft list chain inet psiphon_filter output | head -1
```

### DNS Leaks

**What you see:**
```
DNS queries visible as your real IP
```

**Fix:**
```bash
# 1. Restart DNS
sudo systemctl restart systemd-resolved

# 2. Reload VPN
sudo systemctl reload psiphon-tun

# 3. Test
dig @8.8.8.8 google.com

# 4. Run diagnostics
sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose | grep -A 10 "DNS"
```

### High CPU Usage

**What you see:**
```
psiphon-tunnel-core using 50%+ CPU constantly
```

**Fix:**
```bash
# 1. Reduce tunnels
sudo nano /opt/psiphon-tun/psiphon/psiphon.config
# Change "TunnelPoolSize": 2 → 1

# 2. Kill stuck processes
sudo killall -9 psiphon-tunnel-core

# 3. Restart
sudo systemctl restart psiphon-tun

# 4. Monitor
ps aux | grep psiphon-tunnel-core | grep -v grep
```

### IPv6 Not Working

**What you see:**
```
curl --interface PsiphonTUN -6 fails
IPv6 not configured on TUN interface
```

**Fix:**
```bash
# IPv6 needs 10-30 seconds to setup
sleep 30

# Check if assigned
ip -6 addr show PsiphonTUN

# If still not assigned, full restart
sudo systemctl restart psiphon-tun
sleep 30
ip -6 addr show PsiphonTUN

# Test
curl --interface PsiphonTUN -6 https://ifconfig.me
```

## Emergency Recovery

### Stuck Lock File

```bash
sudo rm -f /run/psiphon-tun.lock /run/psiphon-tun.pid
sudo systemctl restart psiphon-tun
```

### Complete Reset

```bash
# Remove everything
sudo ./Psiphon-Linux-VPN-Service-Setup.sh uninstall

# Wait
sleep 5

# Reinstall
sudo ./Psiphon-Linux-VPN-Service-Setup.sh install
```

### No Internet Access (Kill Switch Activated)

```bash
# Stop VPN (removes kill switch)
sudo systemctl stop psiphon-tun

# Wait a moment
sleep 2

# Restart when ready
sudo systemctl start psiphon-tun
```

## Debug Steps

```bash
# Run in order:

# 1. Full diagnostics
sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose > /tmp/diag.txt
less /tmp/diag.txt

# 2. Check service
sudo systemctl status psiphon-tun -l

# 3. Check process
ps aux | grep psiphon-tunnel-core | grep -v grep

# 4. Check interface
ip addr show PsiphonTUN

# 5. Check routes
ip route | grep PsiphonTUN

# 6. Check firewall
sudo nft list chain inet psiphon_filter output | head -3

# 7. Check logs
sudo journalctl -u psiphon-tun -n 100

# 8. Test connection
curl --interface PsiphonTUN https://ifconfig.me
```

---

Not found here? Check [FAQ](FAQ.md) or [Commands Reference](COMMANDS.md)
