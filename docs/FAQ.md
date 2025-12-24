# Frequently Asked Questions

## Installation

**Q: Do I need root access?**
A: Yes. Install requires sudo/root.

**Q: What Linux versions work?**
A: Ubuntu 22.04+, Debian 11+, Fedora 35+, or any systemd-based Linux.

**Q: Can I use this on Windows/Mac?**
A: No, Linux only. Use native Psiphon app on other platforms.

**Q: How much disk space?**
A: ~50MB in `/opt/psiphon-tun/`

## Configuration

**Q: What's the difference between reload and restart?**
A: Reload = quick, keeps kill switch. Restart = full rebuild, slower.

**Q: How do I change the VPN region?**
A: Edit `/opt/psiphon-tun/psiphon/psiphon.config`, set `"EgressRegion": "US"` (or CA, GB, AU, etc.)

**Q: Can I use multiple tunnels for speed?**
A: Yes, set `"TunnelPoolSize": 2` or 3. Uses more CPU. Restart Psiphon after.

**Q: Is obfuscation always needed?**
A: No, but it helps avoid detection. Keep enabled unless you have compatibility issues.

**Q: Can I limit bandwidth?**
A: Yes, add to config:
```json
"LimitDownstreamBytesPerSecond": 1000000,
"LimitUpstreamBytesPerSecond": 500000
```

## Usage

**Q: How do I use the SOCKS proxy?**
A: Port 1081. In Firefox: Settings → Network → Proxy → SOCKS Host: 127.0.0.1:1081

**Q: What's the HTTP proxy port?**
A: 8081. Use for browsers that don't support SOCKS.

**Q: Can other apps use the VPN?**
A: Yes, they automatically route through the TUN interface. Or use SOCKS/HTTP proxy for specific apps.

**Q: How do I check if VPN is working?**
A: `curl --interface PsiphonTUN https://ifconfig.me` should show a different IP.

**Q: Can I auto-start on boot?**
A: Yes: `sudo systemctl enable psiphon-tun`

## Connectivity

**Q: VPN won't connect. What do I do?**
A: See [Troubleshooting - No Internet Access](TROUBLESHOOTING.md#no-internet-after-starting)

**Q: Disconnects after 5 minutes. Why?**
A: Probably timeout too short. Change `"EstablishTunnelTimeoutSeconds": 300` in config.

**Q: Can I use WARP with Psiphon?**
A: Psiphon → WARP chain is possible but not recommended. Focus on Psiphon alone.

**Q: Why is connection slow?**
A: Try different region, reduce tunnels, or disable obfuscation (less secure).

## Security

**Q: What is the kill switch?**
A: Firewall rule that blocks ALL traffic if VPN disconnects. Always on for safety.

**Q: Is DNS leaking?**
A: Run: `sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose` and check "DNS Leak Detection"

**Q: Can it be disabled?**
A: Kill switch? No - it's a security feature. VPN can be stopped to disable it.

**Q: Is IPv6 supported?**
A: Yes, automatically. Setup takes 10-30 seconds.

**Q: Can I trust this?**
A: Code is open source. Psiphon Labs is reputable. Check GitHub for details.

## Troubleshooting

**Q: Service says it's running but no internet.**
A: Wait 15 seconds for tunnel to establish. Then: `sudo systemctl reload psiphon-tun`

**Q: Logs show errors. What now?**
A: See [Troubleshooting](TROUBLESHOOTING.md) or post error in GitHub Issues.

**Q: How do I reset everything?**
A: `sudo ./Psiphon-Linux-VPN-Service-Setup.sh uninstall` then `install`

**Q: How do I uninstall?**
A: `sudo ./Psiphon-Linux-VPN-Service-Setup.sh uninstall`

**Q: Stuck? What's the nuclear option?**
A: Full reset:
```bash
sudo ./Psiphon-Linux-VPN-Service-Setup.sh uninstall
sleep 5
sudo ./Psiphon-Linux-VPN-Service-Setup.sh install
```

## Performance

**Q: How do I make it faster?**
A: Try `"EstablishTunnelTimeoutSeconds": 60` and `"TunnelPoolSize": 2`

**Q: How do I make it more stable?**
A: Use `"EstablishTunnelTimeoutSeconds": 600` and `"TunnelPoolSize": 1`

**Q: What if it's using too much CPU?**
A: Reduce `"TunnelPoolSize"` to 1 and/or restart: `sudo systemctl restart psiphon-tun`

**Q: Can I see how much bandwidth it uses?**
A: Check process: `ps aux | grep psiphon-tunnel-core`

## Advanced

**Q: Can I run multiple instances?**
A: Not recommended. One VPN is enough.

**Q: Can I edit the firewall rules?**
A: Advanced only. Rules are auto-generated. Edit at your own risk.

**Q: Can I use with other VPNs?**
A: Only as a chain (Psiphon → other VPN). Not recommended.

**Q: Where are the logs?**
A: 
- Systemd: `sudo journalctl -u psiphon-tun -f`
- Script logs: `/opt/psiphon-tun/psiphon-tun.log`
- Psiphon logs: `/opt/psiphon-tun/psiphon-core.log`

## Still Need Help?

- [Commands Reference](COMMANDS.md) - All commands
- [Troubleshooting](TROUBLESHOOTING.md) - Fix problems
- [Configuration](CONFIGURATION.md) - Change settings
- [Usage & Commands](USAGE.md) - How to use
