# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Agent Armor, please report it responsibly.

**Email:** [security@stylusnexus.com](mailto:security@stylusnexus.com)

You can also use GitHub's **Report a vulnerability** link on the repository's
Security tab when private vulnerability reporting is available. If that option
is not shown, use the email address above. Do not open a public issue for an
unfixed vulnerability.

Please include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential impact assessment

We will acknowledge your report within 48 hours and aim to provide a fix within 7 days for critical issues.

## Scope

This policy covers:

- The `@stylusnexus/agentarmor` npm package
- The `@stylusnexus/agentarmor-ml` npm package
- Detection pattern bypasses (i.e., adversarial content that evades all detectors)

Pattern bypasses are expected and not treated as critical vulnerabilities — they are improvement opportunities. However, we appreciate reports of novel bypass techniques as they help us strengthen detection.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |
| < 0.2.0 | No        |
