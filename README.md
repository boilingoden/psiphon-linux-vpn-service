# Psiphon Linux VPN Service

System-wide Psiphon VPN service for Linux with absolute kill-switch protection. Zero-trust networking model: all traffic must go through VPN or is blocked; non-root user isolation for Psiphon binary.

[![ShellCheck](https://github.com/boilingoden/psiphon-linux-vpn-service/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/boilingoden/psiphon-linux-vpn-service/actions/workflows/shellcheck.yml)

## 🛡️ Key Features

- **Absolute Kill Switch**
  - Fail-closed security model
  - No bypass routes or exceptions
  - Full IPv4/IPv6 protection

- **Zero Trust Security**
  - Default deny-all policy
  - DNS leak prevention
  - Dedicated **non-root user isolation**

## 📋 Requirements

- Linux with systemd (only if you want to use it)
- Root access
- nftables

## 🚀 Installation

```bash
git clone https://github.com/boilingoden/psiphon-client-linux-service.git
cd psiphon-client-linux-service
sudo ./Psiphon-Linux-VPN-Service-Setup.sh install
```

## � Quick Start

```bash
# Show all available commands
sudo ./Psiphon-Linux-VPN-Service-Setup.sh help

# Start VPN
sudo systemctl start psiphon-tun

# Stop VPN
sudo systemctl stop psiphon-tun

# Check status
sudo systemctl status psiphon-tun

# Keep kill-switch on and restart only the Psiphon binary
sudo systemctl reload psiphon-tun

# Restart without keeping kill-switch
sudo systemctl Restart psiphon-tun
```

→ **Full documentation in [docs/](docs/) directory** ✨

## 📚 Documentation

Start here:
- **[Getting Started](docs/GETTING-STARTED.md)** (5 min) - Install & test
- **[Commands Reference](docs/COMMANDS.md)** - All commands
- **[Configuration](docs/CONFIGURATION.md)** - Settings + 5 presets
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Fix problems
- **[FAQ](docs/FAQ.md)** - Quick answers
- **[Usage & Commands](docs/USAGE.md)** - How to use
- **[Security](docs/SECURITY.md)** - Kill switch, DNS, isolation
- **[Network Setup](docs/NETWORK.md)** - Network details

See [docs/README.md](docs/README.md) for full documentation index.

Configuration: `/opt/psiphon-tun/psiphon/psiphon.config`

## 🔍 Network Info

- Interface: `PsiphonTUN`
- IPv4: `10.200.3.0/24`
- IPv6: `fd42:42:42::/64`

## 🐛 Troubleshooting

```bash
# View logs (script mode)
sudo tail -f /opt/psiphon-tun/psiphon-tun.log

# View logs (systemd service mode)
sudo systemctl status psiphon-tun.service
sudo systemctl status psiphon-binary.service

# Test connection
sudo ./Psiphon-Linux-VPN-Service-Setup.sh status
sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose
```

**See [Troubleshooting](docs/TROUBLESHOOTING.md) guide**

## 📄 License

This is free and unencumbered software released into the public domain - See [LICENSE](LICENSE) file
