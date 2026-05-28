# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch | ✅ Active |
| Older releases | ❌ No support |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in PhishGuard, please report it responsibly:

1. **Email:** Open a [GitHub Security Advisory](../../security/advisories/new) (preferred — keeps the report private)
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested mitigations (optional)

You will receive an acknowledgment within **48 hours** and a resolution timeline within **7 days** for confirmed vulnerabilities.

## Security Design Principles

PhishGuard was built with the following security principles:

- **Credential safety:** Credentials submitted to the fake login page are **immediately discarded** — they are never stored, logged, or transmitted. Only the timestamp of the submission event is recorded.
- **HMAC-signed tracking IDs:** All tracking tokens are HMAC-SHA256 signed to prevent forgery or enumeration.
- **No stored plaintext secrets:** API keys are loaded from environment variables and never committed to version control.
- **HTML sanitization:** All AI-generated HTML is sanitized with `bleach` before storage to prevent stored XSS.
- **Rate limiting:** All public-facing tracking endpoints are rate-limited to prevent abuse and cost attacks.
- **CSRF protection:** All authenticated form endpoints are protected with Flask-WTF CSRF tokens.
- **Secure headers:** Content Security Policy, HSTS, X-Frame-Options, and X-Content-Type-Options are enforced via Flask-Talisman.

## Ethical Use Requirement

This software is intended for **authorized security awareness training only**. Deployment against any organization or individuals without explicit written authorization is outside the intended use and may be illegal. The maintainers are not responsible for misuse.
