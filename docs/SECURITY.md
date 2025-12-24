# Security

## Kill Switch

### What It Is
Firewall rule that **blocks ALL traffic if VPN disconnects**.

### How It Works
1. Firewall policy: `DROP` (all traffic blocked by default)
2. Exception: psiphon-user process can send traffic
3. If Psiphon crashes → traffic blocked immediately
4. If network changes → traffic blocked until reconnected

### Why It Matters
Without it, your IP leaks if VPN crashes. You wouldn't know.

### Testing It

```bash
# 1. Start VPN
sudo systemctl start psiphon-tun
sleep 3

# 2. Verify connected
curl --interface PsiphonTUN https://ifconfig.me
# Should show IP address

# 3. Stop VPN
sudo systemctl stop psiphon-tun

# 4. Try to reach internet (should fail)
timeout 5 curl https://ifconfig.me
# Should timeout/fail (good!)

# 5. Restart VPN
sudo systemctl start psiphon-tun
sleep 3

# 6. Verify working again
curl --interface PsiphonTUN https://ifconfig.me
# Should show IP address
```

### Verify It's Active

```bash
# Check firewall rule
sudo nft list chain inet psiphon_filter output | head -1

# Should show: policy drop

# If missing, it's a security problem!
sudo systemctl restart psiphon-tun
```

## DNS Leak Prevention

### What It Is
DNS queries (how you look up domain names) could leak your real IP.

### How Psiphon Prevents It
1. All DNS configured to go through VPN tunnel
2. Uses Google DNS (8.8.8.8, 8.8.4.4)
3. DNS packets route through TUN interface

### Testing DNS

```bash
# Query Google DNS (should go through VPN)
dig @8.8.8.8 google.com

# Should resolve successfully

# Run full leak test
sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose | grep -A 20 "DNS Leak"
```

### If DNS Leaks

```bash
# Restart DNS service
sudo systemctl restart systemd-resolved

# Reload VPN
sudo systemctl reload psiphon-tun

# Test again
dig @8.8.8.8 google.com
```

## Process Isolation

### What It Is
Psiphon runs as dedicated non-root user (`psiphon-user`).

### Benefits
- If compromised, attacker has limited privileges
- Can't modify system files
- Can't escalate to root directly
- Only has capabilities needed for VPN

### Capabilities Granted
```
CAP_NET_ADMIN     - TUN interface management
CAP_NET_RAW       - Raw socket operations
CAP_NET_BIND_SERVICE - Bind to port 1081, 8081
```

All others are dropped (blocked).

### Verification

```bash
# See psiphon-user exists
id psiphon-user

# See process owner
ps aux | grep psiphon-tunnel-core | grep -v grep
# Should show: psiphon-user (not root)

# Check file permissions
ls -la /opt/psiphon-tun/psiphon/psiphon-tunnel-core
# Should show: psiphon-user:psiphon-group 755
```

## File Permissions

### Config File
```
/opt/psiphon-tun/psiphon/psiphon.config
Permissions: 600 (only psiphon-user can read/write)
Owner: psiphon-user:psiphon-group
```

### Binary
```
/opt/psiphon-tun/psiphon/psiphon-tunnel-core
Permissions: 755 (executable)
Owner: psiphon-user:psiphon-group
```

### Installation Directory
```
/opt/psiphon-tun/
Permissions: 755
Owner: psiphon-user:psiphon-group
```

## Firewall Protection

### Layers

1. **Output Policy: DROP**
   - All traffic blocked by default
   - Whitelist only allowed traffic

2. **psiphon-user Exception**
   - Only psiphon-user can send traffic
   - Regular users blocked

3. **TUN Interface Rule**
   - Traffic via PsiphonTUN allowed
   - Direct internet traffic blocked

### Checking Rules

```bash
# View all firewall rules
sudo nft list ruleset

# View OUTPUT chain only
sudo nft list chain inet psiphon_filter output

# Check specific rule
sudo nft list chain inet psiphon_filter output | grep "policy\|skuid\|PsiphonTUN"
```

## IPv6 Security

### What Could Go Wrong
IPv6 traffic could bypass VPN and leak real IP.

### How Psiphon Handles It
1. IPv6 subnet: `fd42:42:42::/64` (isolated)
2. IPv6 routes through TUN interface
3. Firewall rules apply to IPv6 too

### Testing IPv6

```bash
# Check if IPv6 assigned
ip -6 addr show PsiphonTUN

# Should show address starting with fd42:42:42

# Test connectivity
curl --interface PsiphonTUN -6 https://ifconfig.me

# Should work after ~30 seconds
```

## Binary Integrity

### How It Works
Psiphon binary is verified during download:

```bash
# Check is automatic during:
sudo ./Psiphon-Linux-VPN-Service-Setup.sh install

# Manual check
sha256sum /opt/psiphon-tun/psiphon/psiphon-tunnel-core
```

### Updates
Binary auto-updates from GitHub (bypasses censorship):

```bash
sudo ./Psiphon-Linux-VPN-Service-Setup.sh update

# Or automatic during:
sudo systemctl reload psiphon-tun
```

## Best Practices

1. **Always verify kill switch is active**
   ```bash
   sudo nft list chain inet psiphon_filter output | head -1
   # Should show: policy drop
   ```

2. **Check DNS doesn't leak**
   ```bash
   sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose | grep "DNS Leak"
   ```

3. **Use stable configurations**
   See [Configuration](CONFIGURATION.md) for recommended settings.

4. **Keep software updated**
   Binary updates automatically. Check: `sudo systemctl reload psiphon-tun`

5. **Use auto-start on servers**
   ```bash
   sudo systemctl enable psiphon-tun
   ```
   Ensures VPN always active, kill switch always protecting.

6. **Monitor regularly**
   ```bash
   sudo journalctl -u psiphon-tun -f
   ```
   Watch for disconnects or errors.

---

See: [Troubleshooting](TROUBLESHOOTING.md) | [Network](NETWORK.md)
