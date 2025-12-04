# Contributing to Psiphon Linux VPN Service

Thank you for your interest in contributing to the Psiphon Linux VPN Service! We welcome contributions from the community, but all changes must maintain our strict security standards.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone <https://github.com/your-username/psiphon-linux-vpn-service.git>
   cd psiphon-linux-vpn-service
   ```
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Guidelines

### Security First

- **Never compromise security for convenience or features**
- The kill switch must always remain active and functional
- All changes must maintain the zero-trust networking model
- Any modifications to firewall rules must preserve the fail-closed design
- Test thoroughly to ensure no traffic leaks occur

### Code Style

- Use POSIX shell scripting standards
- Follow existing code formatting and conventions
- Add comments for complex logic
- Keep functions focused and single-purpose
- Use descriptive variable names

### Logging

- Use the provided logging functions: `log()`, `error()`, `success()`, `warning()`
- All output should use consistent formatting
- Include timestamps in log messages
- Log security-relevant events appropriately

### Testing

Before submitting a pull request, ensure:

1. **Security Testing**
   - Verify the kill switch blocks all traffic when expected
   - Test both IPv4 and IPv6 functionality
   - Check for DNS leaks
   - Confirm process isolation is maintained

2. **Functional Testing**
   - Test on a clean Ubuntu 20.04+ or similar system
   - Verify service start, stop, and reload operations
   - Test network transitions and recovery
   - Check systemd integration

3. **Regression Testing**
   - Run the full service start/stop cycle
   - Verify all existing features still work
   - Test system suspension/resume

### Documentation

- Update README.md if behavior changes
- Add comments to complex code sections
- Update this CONTRIBUTING.md if adding new processes
- Document any new configuration options

## Submission Process

1. **Commit your changes** with clear, descriptive messages:
   ```bash
   git commit -m "Add feature: description of changes"
   ```

2. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Submit a Pull Request**:
   - Provide a clear title and description
   - Reference any related issues
   - Explain the security implications of your changes
   - Include test results

## Pull Request Requirements

Your pull request will be reviewed for:

- **Security**: Does it maintain the security model?
- **Code Quality**: Is the code clear and well-documented?
- **Testing**: Have changes been thoroughly tested?
- **Compatibility**: Does it work on supported platforms?
- **Documentation**: Are changes properly documented?

## Areas for Contribution

### High Priority

- Security vulnerability fixes
- Process isolation improvements
- Kill switch robustness
- DNS leak prevention enhancements
- IPv6 support improvements

### Welcome Contributions

- Documentation improvements
- Bug fixes
- Performance optimizations (without compromising security)
- Better error messages
- Additional logging/debugging capabilities
- Test coverage improvements

### Please Discuss First

For major architectural changes or significant new features:
1. Open an issue to discuss the proposal
2. Get feedback from maintainers
3. Discuss security implications
4. Plan the implementation approach

## Security Considerations

When contributing, always consider:

- **Fail-closed design**: Does this maintain the fail-closed principle?
- **User isolation**: Can users access what they shouldn't?
- **Network protection**: Are all traffic paths properly filtered?
- **Process capabilities**: Are we using minimum necessary privileges?
- **Error handling**: Do errors result in safe (blocking) states?

## Testing Commands

```bash
# Verify installation
sudo ./Psiphon-Linux-VPN-Service-Setup.sh install

# Check status
sudo ./Psiphon-Linux-VPN-Service-Setup.sh status

# Run diagnostics
sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose

# View logs
tail -f /opt/psiphon-tun/psiphon-tun.log

# Check firewall rules
sudo nft list chain inet psiphon_filter output

# Stop service
sudo ./Psiphon-Linux-VPN-Service-Setup.sh stop

# Clean up
sudo ./Psiphon-Linux-VPN-Service-Setup.sh uninstall
```

## Code Review Process

1. At least one maintainer will review your PR
2. Security review is mandatory for all changes
3. Automated tests (if available) will be run
4. Discussion may occur in the PR comments
5. Changes may be requested before approval
6. Once approved, your PR will be merged

## Reporting Bugs

If you find a bug:

1. **Security bugs**: Email <mailto:security@psiphon.ca> instead of opening a public issue
2. **Other bugs**: Open an issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs. actual behavior
   - System information (OS, version, etc.)
   - Relevant logs or error messages

## Community

- Treat all community members with respect
- Follow the Code of Conduct in all interactions
- Ask questions if anything is unclear
- Help other contributors when possible
- Provide constructive feedback

## License

By contributing to this project, you agree that your contributions will be licensed under the project's existing license.

## Questions?

Feel free to open an issue or contact the maintainers at <mailto:security@psiphon.ca> for questions about contributing.

Thank you for helping make the Psiphon Linux VPN Service more secure and reliable!
