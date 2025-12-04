# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in the Psiphon Linux VPN Service, please report it responsibly by emailing <mailto:security@psiphon.ca> instead of using the public issue tracker.

Please include:
- Description of the vulnerability
- Steps to reproduce (if applicable)
- Affected versions
- Proposed fix (if available)

## Security Architecture

This VPN service implements a zero-trust networking model with absolute security prioritization:

### Core Security Principles

1. **Security Over Functionality**: The system always chooses security over convenience or features
2. **Fail-Closed Design**: All traffic is blocked by default; only explicitly allowed traffic passes through
3. **No Exceptions**: The kill switch remains active during all operations without compromise

### Network Kill Switch

- All outbound traffic is blocked by default using nftables (`OUTPUT DROP` policy)
- Only the `psiphon-user` process can establish external connections
- Network transitions immediately default to blocking all traffic
- Works across both IPv4 and IPv6 stacks

### Process Isolation

- Psiphon runs as non-root `psiphon-user` with minimal required capabilities:
  - `CAP_NET_ADMIN` - TUN interface management
  - `CAP_NET_RAW` - Raw socket operations for tunneling
  - `CAP_NET_BIND_SERVICE` - Port binding for proxy services
- All other capabilities are dropped via systemd `CapabilityBoundingSet`

### Traffic Routing

- All traffic forced through the TUN interface (`PsiphonTUN`)
- Dedicated subnets: `10.200.3.0/24` (IPv4) and `fd42:42:42::/64` (IPv6)
- DNS requests isolated from the system resolver to prevent leaks

### File Permissions

- Binaries: 755 (executable by owner/group)
- Configuration files: 600 (readable only by owner)
- All files owned by `psiphon-user:psiphon-group`

## Security Best Practices for Users

1. **Verify Installation**: Check SHA256 checksums during installation
2. **Keep Updated**: Regularly update the VPN service for security patches
3. **Monitor Status**: Use the `diagnose` command to verify security status:
   ```bash
   sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose
   ```
4. **Check Firewall Rules**: Verify kill switch is active:
   ```bash
   sudo nft list chain inet psiphon_filter output
   ```

## Security Testing Recommendations

Before deploying in production:

1. **Kill Switch Verification**
   - Stop the service and verify no traffic leaks
   - Test network transitions
   - Verify recovery after system suspension

2. **DNS Leak Prevention**
   - Test DNS queries are routed through the tunnel
   - Verify no system DNS queries leak
   - Check both IPv4 and IPv6 DNS resolution

3. **Network Isolation**
   - Confirm only `psiphon-user` can access the network
   - Test local network access restrictions
   - Verify no bypass routes exist

## Supported Versions

Security updates are provided for the current version of the VPN service. Users should keep their installations updated to the latest version.

## Known Limitations

- Requires root/sudo privileges for installation and operation
- Effective only on Linux systems (tested on Ubuntu 20.04+ and Fedora 39+)
- Does not protect against kernel vulnerabilities or rootkits

## Compliance

This service is designed with security-first principles following industry best practices for:
- Process isolation and capability droppig
- Firewall and kill switch implementation
- Zero-trust network architecture
- Fail-safe error handling

## Security Updates

Security patches will be released as needed. Users will be notified through GitHub releases and the project repository.

---

**Last Updated**: December 2025
**Version**: 1.0
