# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.0.1 (upcoming, not yet published) | Reports accepted; no released version yet |

## Reporting a Vulnerability

This library handles PKI infrastructure and X.509 certificate validation for ICP-Brasil.
Security vulnerabilities must be reported responsibly and **never** disclosed publicly before a fix is available.

### How to report

Send an e-mail to **ti-ses.saude@goias.gov.br** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The affected versions (if known)
- Any suggested remediation (optional)

Please encrypt sensitive reports using our PGP key if available on [keys.openpgp.org](https://keys.openpgp.org).

### Response timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | 2 business days |
| Initial assessment | 5 business days |
| Fix or workaround | Depends on severity — critical issues are prioritised |
| Public disclosure | Coordinated with the reporter after a fix is released |

### Scope

Reports are in scope for:

- Bypass of certificate chain validation logic
- Incorrect revocation status (OCSP / CRL)
- Hash integrity bypass (SHA-512 / SHA-256 validation in `HashValidator`)
- SSRF vulnerabilities in the download pipeline (AIA, OCSP, CRL URLs)
- Unsafe deserialization or path traversal in storage backends (filesystem / S3)
- Dependency vulnerabilities with a direct exploit path in this library

Out of scope: issues exclusively in test code, documentation, or dependencies that have no known exploit.

### Disclosure policy

We follow the principles of **responsible disclosure**. Once a fix is released we will publish a security advisory on the GitHub repository. Credit will be given to the reporter unless they prefer to remain anonymous.

## Residual risks and operational requirements

The trust chain (pinned TLS to ITI → SHA-512 validation → storage → in-memory index with write access restricted to the load pipeline) has two **documented residual risks** that operators must mitigate:

1. **Hash and bundle share the same origin and channel.** ITI does not publish a detached signature for the CA bundle; the SHA-512 file is downloaded from the same host over the same TLS channel. Integrity validation therefore protects against corruption and storage tampering of a single artifact, not against a full compromise of the origin. Mitigation: TLS is pinned to a dedicated trust store (not the JVM defaults).
2. **Storage (filesystem/S3) must have restrictive ACLs.** An attacker with write access to the storage can replace the *pair* (bundle + hash), which passes local revalidation until the next remote sync detects the divergence. Restrict write access to the artifact directory/bucket to the application identity only.

### PGP key for release verification

Release artifacts are signed with the key below. Verify it via public keyservers (`keyserver.ubuntu.com`, `keys.openpgp.org`):

```
Key ID:      566A199A481E3355
Fingerprint: 8EF6 6D44 5A97 6C0A 2C3B 4FB5 566A 199A 481E 3355
UID:         SES-GO TI <ti-ses.saude@goias.gov.br>
```
