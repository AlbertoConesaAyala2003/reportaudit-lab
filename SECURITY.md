# Security Policy

## Supported versions

| Version | Security support | End of security support |
| --- | --- | --- |
| 1.x | Supported from the release of 1.0.0 | Five years after the release of 1.0.0, or 2031-10-31, whichever is later |
| < 1.0 | Unsupported | — |

## Reporting a vulnerability

Send a private report through [Report a vulnerability](https://github.com/AlbertoConesaAyala2003/reportaudit-lab/security/advisories/new). Include the affected version, steps to reproduce the problem, the impact you observed and any suggested fix. Keep the details in the private report until disclosure has been coordinated.

## What to expect

- We will acknowledge your report within three business days.
- We will provide an initial assessment within ten business days.
- We aim to release a fix and publish a security advisory within 90 days of receiving the report. We will credit you unless you prefer to remain anonymous.

## Safe harbour

We will not take legal action against researchers who act in good faith, avoid privacy violations and service disruption, and give us reasonable time to fix the issue before disclosing it.

## Verifying our releases

Starting with 1.0.0, releases will include a CycloneDX software bill of materials, SHA-256 checksums and Sigstore-signed provenance attestations. Download the release files and run the following commands in the download directory. For a later release, replace `1.0.0` with its version.

```sh
sha256sum -c SHA256SUMS
gh attestation verify reportaudit-1.0.0.tar.gz --repo AlbertoConesaAyala2003/reportaudit-lab
```
