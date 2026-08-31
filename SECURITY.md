# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.0.1-SNAPSHOT (development) | :white_check_mark: |

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
