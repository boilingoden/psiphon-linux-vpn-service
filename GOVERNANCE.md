# Governance

## Project Overview

The Psiphon Linux VPN Service is a security-focused VPN implementation that prioritizes user privacy and system security above all other considerations. This document outlines how the project is governed and how decisions are made.

## Core Principles

1. **Security First**: Security is never compromised for convenience, features, or performance
2. **Transparency**: Decisions and processes are transparent to the community
3. **Community Driven**: Community feedback is valued and considered
4. **Privacy Focused**: User privacy and anonymity are fundamental design principles

## Project Structure

### Maintainers

Project maintainers are responsible for:
- Reviewing and merging pull requests
- Managing releases
- Responding to security reports
- Setting project direction
- Maintaining code quality standards
- Ensuring security principles are upheld

### Contributors

Contributors are community members who:
- Report bugs and suggest improvements
- Submit pull requests with code changes
- Help with documentation
- Test new features and releases
- Participate in discussions

## Decision Making

### Minor Changes

Minor changes (documentation updates, small bug fixes, code style improvements) can be approved and merged by a single maintainer after review.

### Major Changes

Major changes require:
1. Detailed issue discussion or RFC (Request for Comments)
2. Consensus among maintainers
3. Security review
4. Testing on supported platforms
5. Documentation updates

Major changes include:
- New features that affect user experience
- Architectural changes
- Changes to security mechanisms
- Changes to system integration points
- Breaking changes

### Security Decisions

All security-related decisions:
- Are made with the highest priority
- Require maintainer consensus
- Are documented clearly
- Include implementation guidance
- May result in immediate releases if critical

## Release Process

### Release Types

- **Security Releases**: For critical security fixes (released immediately after verification)
- **Major Releases**: For significant new features or breaking changes
- **Minor Releases**: For non-breaking improvements and bug fixes
- **Patch Releases**: For urgent bug fixes

### Release Criteria

All releases must:
- Pass security review
- Be tested on supported platforms (Ubuntu 20.04+, Fedora 39+)
- Include updated CHANGELOG
- Include clear documentation of changes
- Maintain backward compatibility (except major versions)

## Security Vulnerabilities

### Reporting

Security vulnerabilities must be reported to <mailto:security@psiphon.ca> rather than posted publicly.

### Disclosure Policy

1. **Report received** → Acknowledged within 24 hours
2. **Assessment** → Severity and impact evaluated
3. **Fix developed** → Security patch created and tested
4. **Embargo period** → Patch tested for 7-14 days before release
5. **Public disclosure** → Release notes published with full details
6. **Follow-up** → Security advisory issued if needed

## Contribution Guidelines

### Acceptance Criteria

Contributions are accepted if they:
1. **Maintain security standards** - No compromises on security
2. **Follow project conventions** - Code style and structure
3. **Include testing** - Comprehensive tests for new features
4. **Are well documented** - Clear comments and documentation
5. **Pass review** - Approved by at least one maintainer

### Code Review Standards

All code reviews evaluate:
- **Functionality**: Does it work as intended?
- **Security**: Does it maintain security principles?
- **Quality**: Is the code clear and maintainable?
- **Testing**: Is it adequately tested?
- **Documentation**: Is it properly documented?

## Communication Channels

- **GitHub Issues**: Bug reports, feature requests, discussions
- **GitHub Discussions**: Community discussions and Q&A
- **Email**: <mailto:security@psiphon.ca> for security issues
- **Pull Requests**: Code review and discussion

## Conflict Resolution

### Disagreements

If there are disagreements about a decision:
1. Discuss the issue respectfully in the relevant channel
2. Present evidence and reasoning
3. Seek consensus among maintainers
4. Document the decision rationale
5. Move forward once decided

### Code of Conduct Violations

Violations of the Code of Conduct will be handled through the process documented in CODE_OF_CONDUCT.md.

## Project Maintenance

### Maintenance Commitment

The project is actively maintained with:
- Regular security reviews
- Prompt response to security reports
- Timely bug fixes
- Documentation updates
- Testing on new platform versions

### Deprecation Policy

When features need to be deprecated:
1. Clear announcement in release notes
2. At least one minor version with deprecation warning
3. Final removal in next major version
4. Migration guide provided if applicable

## Community Recognition

Contributors are recognized for their work through:
- Acknowledgment in CHANGELOG
- Credit in project documentation
- Mention in release notes
- Recognition in the community

## Amendments

This governance document may be amended as the project evolves. Major amendments will:
1. Be proposed as an issue
2. Be discussed by the community
3. Be approved by maintainers
4. Be clearly documented

## License

This project is licensed under the terms specified in the LICENSE file. All contributions must be compatible with this license.

---

**Last Updated**: December 2025

For questions about governance, please open an issue or contact the maintainers at <mailto:security@psiphon.ca>.
