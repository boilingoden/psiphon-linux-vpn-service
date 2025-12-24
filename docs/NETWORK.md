# Network Setup

## Network Architecture

```
Your Apps
    ↓ (all traffic)
TUN Interface (PsiphonTUN)
    ↓ (encrypted)
Psiphon Process (psiphon-user)
    ↓ (via ISP)
Psiphon Servers
    ↓ (decrypted)
Internet
```

## Network Configuration

### TUN Interface
```
Name: PsiphonTUN
IPv4: 10.200.3.0/24 (gateway: 10.200.3.1)
IPv6: fd42:42:42::/64 (gateway: fd42:42:42::1)
```

### Proxy Ports
```
SOCKS5: 127.0.0.1:1081
HTTP:   127.0.0.1:8081
```

### DNS
```
IPv4: 8.8.8.8, 8.8.4.4 (Google)
IPv6: 2001:4860:4860::8888, 2001:4860:4860::8844
```

## Viewing Network Status

```bash
# See TUN interface
ip addr show PsiphonTUN

# See all routes
ip route show

# See IPv6
ip -6 addr show PsiphonTUN
ip -6 route show

# See active connections
ss -tunap | grep psiphon

# Check DNS
cat /etc/resolv.conf
```

## How Traffic Routes

All traffic is blocked by default (firewall policy: DROP).

**Exceptions:**
1. Traffic from psiphon-user process → allowed
2. Loopback traffic (127.0.0.1) → allowed
3. Established connections → allowed

**Everything else:** BLOCKED

This is the **kill switch**.

## Firewall Rules

Psiphon uses **nftables** (modern firewall):

```bash
# View rules
sudo nft list ruleset

# View output chain specifically
sudo nft list chain inet psiphon_filter output | head -10
```

Key rules:
- `policy drop` - all traffic blocked by default
- `meta skuid <psiphon_user_id>` - psiphon-user can send traffic
- `oifname "PsiphonTUN"` - traffic via TUN interface allowed

## Local Network Access

By design, kill switch blocks local network (192.168.x.x, 10.x.x.x) unless routed through VPN.

**To access local services:**
```bash
# Use SOCKS proxy
curl --socks5 127.0.0.1:1081 http://192.168.1.100:8000

# Or route through TUN
curl --interface PsiphonTUN http://192.168.1.100:8000  # Usually blocked
```

## IPv6 Router Advertisement (RA)

IPv6 setup requires waiting for Router Advertisement processing:

```bash
# Takes 10-30 seconds after start
sleep 30

# Check if IPv6 is assigned
ip -6 addr show PsiphonTUN

# Should show something like: inet6 fd42:42:42::1/64
```

This is normal and expected.

## Testing Network

```bash
# Basic connectivity
curl --interface PsiphonTUN https://ifconfig.me

# DNS resolution
dig @8.8.8.8 google.com

# IPv6 (after 30 seconds)
curl --interface PsiphonTUN -6 https://ifconfig.me

# Trace route through VPN
mtr --interface PsiphonTUN google.com

# Monitor ongoing connections
watch -n 1 'ss -tunap | grep psiphon'
```

## Troubleshooting Network

```bash
# TUN interface not up?
sudo systemctl restart psiphon-tun

# Routes not configured?
ip route | grep PsiphonTUN  # Should have entries

# DNS not resolving?
dig @8.8.8.8 google.com  # Should return IP

# Kill switch not active?
sudo nft list chain inet psiphon_filter output | grep "policy drop"

# Firewall blocking traffic?
sudo nft list chain inet psiphon_filter output | head -20
```

---

For details see: [Security](SECURITY.md) | [Troubleshooting](TROUBLESHOOTING.md)
