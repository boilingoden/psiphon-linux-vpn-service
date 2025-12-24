# Psiphon Linux VPN Service - Documentation

Welcome! Pick what you need:

## 🚀 Quick Start
**First time?** → [Getting Started](GETTING-STARTED.md) (5 minutes)

## 📖 Main Guides
- **[Configuration](CONFIGURATION.md)** - All settings explained + 5 presets
- **[Usage & Commands](USAGE.md)** - All operations and systemd management
- **[Troubleshooting](TROUBLESHOOTING.md)** - Fix problems with diagnostics
- **[FAQ](FAQ.md)** - Quick answers to common questions

## 🔗 Reference
- **[Commands Reference](COMMANDS.md)** - All commands in one place
- **[Network Setup](NETWORK.md)** - Network configuration details
- **[Security](SECURITY.md)** - Kill switch, DNS, isolation explained

---

## Navigation by Task

| I want to... | Go to... |
|---|---|
| Get VPN working now | [Getting Started](GETTING-STARTED.md) |
| Copy a ready-made config | [Configuration](CONFIGURATION.md#configuration-profiles) |
| Understand all settings | [Configuration](CONFIGURATION.md#parameters) |
| See all commands | [Commands Reference](COMMANDS.md) |
| Fix something broken | [Troubleshooting](TROUBLESHOOTING.md) |
| Use SOCKS proxy | [Usage & Commands](USAGE.md#socks-proxy) |
| Verify kill switch | [Security](SECURITY.md#kill-switch) |
| Check DNS security | [Security](SECURITY.md#dns-leak-prevention) |
| Monitor in real-time | [Usage & Commands](USAGE.md#monitoring) |
| Optimize performance | [Configuration](CONFIGURATION.md#optimization) |
| Find quick answers | [FAQ](FAQ.md) |

---

## 📚 Reading by Level

### Beginner (Want it working)
1. [Getting Started](GETTING-STARTED.md)
2. [Configuration](CONFIGURATION.md) - pick a profile
3. [FAQ](FAQ.md) - keep for reference

### Intermediate (Want to understand)
1. [Getting Started](GETTING-STARTED.md)
2. [Usage & Commands](USAGE.md)
3. [Configuration](CONFIGURATION.md)
4. [Troubleshooting](TROUBLESHOOTING.md)

### Advanced (Want everything)
1. All guides above
2. [Network Setup](NETWORK.md)
3. [Security](SECURITY.md)
4. [Commands Reference](COMMANDS.md)

---

## 📋 Document Overview

| Guide | Size | Reading Time | Purpose |
|-------|------|--------------|---------|
| Getting Started | 3 KB | 5 min | Install & test |
| Configuration | 8 KB | 15 min | Settings & profiles |
| Usage & Commands | 6 KB | 15 min | Operations |
| Troubleshooting | 7 KB | 20 min | Fix problems |
| FAQ | 4 KB | 10 min | Quick answers |
| Commands Reference | 2 KB | 5 min | Command lookup |
| Network Setup | 3 KB | 10 min | Network details |
| Security | 3 KB | 10 min | Security features |

---

## 🎯 Key Commands

```bash
# Quick lookup - see COMMANDS.md for complete list

# Basic
sudo systemctl start psiphon-tun
sudo systemctl status psiphon-tun
curl --interface PsiphonTUN https://ifconfig.me

# Diagnosis
sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose

# Config
sudo nano /opt/psiphon-tun/psiphon/psiphon.config
sudo systemctl reload psiphon-tun
```

See [Commands Reference](COMMANDS.md) for full list.

---

## ✨ Highlights

- ✅ 5 pre-made configurations (copy-paste ready)
- ✅ All commands in one reference page
- ✅ Common issues with fixes
- ✅ No repeated information
- ✅ Clean, focused guides
- ✅ Quick navigation

---

## 🆘 In a Hurry?

**Everything broken?** Run:
```bash
sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose
```

→ Then check [Troubleshooting](TROUBLESHOOTING.md#common-issues)

**Can't connect?** See [Troubleshooting](TROUBLESHOOTING.md#no-internet-access)

**Something confusing?** Check [FAQ](FAQ.md)

---

**Start with:** [Getting Started](GETTING-STARTED.md) or [Commands Reference](COMMANDS.md)
