# Getting Started - 5 Minutes

## Prerequisites (30 seconds)

```bash
# Check you have what you need
cat /etc/os-release              # Linux with systemd?
sudo whoami                      # Root/sudo access?
df -h /opt                       # 50MB disk space?
```

**Have all three?** Continue.

## Install (2 minutes)

```bash
# Dependencies
sudo apt update
sudo apt install git wget curl unzip nftables -y

# Get Psiphon
git clone https://github.com/boilingoden/psiphon-linux-vpn-service.git
cd psiphon-linux-vpn-service

# Install
sudo ./Psiphon-Linux-VPN-Service-Setup.sh install
```

Done when you see: `SUCCESS: Psiphon TUN setup complete`

## Start & Test (2 minutes)

```bash
# Start VPN
sudo systemctl start psiphon-tun
sleep 10

# Test
curl --interface PsiphonTUN https://ifconfig.me
# Shows IP address? Success!

# Auto-start on boot
sudo systemctl enable psiphon-tun
```

## What Now?

- **See all commands:** [Commands Reference](COMMANDS.md)
- **Customize config:** [Configuration](CONFIGURATION.md)
- **Something broken?** [Troubleshooting](TROUBLESHOOTING.md)
- **Quick answers:** [FAQ](FAQ.md)

## Kill Switch Test

```bash
# Verify it blocks traffic if VPN dies

sudo systemctl stop psiphon-tun
timeout 5 curl https://ifconfig.me  # Should fail (good!)
sudo systemctl start psiphon-tun
sleep 3
curl --interface PsiphonTUN https://ifconfig.me  # Should work
```

---

✅ **Done!** VPN is installed and working.

Next: [Commands Reference](COMMANDS.md) or [Configuration](CONFIGURATION.md)
