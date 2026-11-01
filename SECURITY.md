# Security Policy

59k GmbH (Vienna, Austria) maintains cysec-scanner. People run it inside their own networks, so we take its security seriously, and we welcome reports from the security community.

## Supported versions

| Version | Security fixes |
|---|---|
| The latest release (currently 0.1.x) and `master` | Yes |
| Older releases | No. Please upgrade. |

Security fixes ship as a new patch version and are announced in a GitHub Security Advisory.

## Reporting a vulnerability

**Please do not report security vulnerabilities in public GitHub issues, discussions or pull requests.**

Report them privately through either channel:

1. **GitHub private vulnerability reporting** (preferred): use the "Report a vulnerability" button on this repository's *Security* tab. The report stays private between you and the maintainers.
2. **Email:** security@59k.ai

As far as you can, please include:

- the affected version or commit
- what the issue is and what impact it has
- steps to reproduce it, or a proof of concept
- a suggested mitigation, if you have one

You can report in English or German.

## What to expect

| Step | Target |
|---|---|
| We acknowledge your report | within 3 business days |
| Initial assessment and severity rating (CVSS) | within 10 business days |
| Fix or mitigation for critical and high issues | within 30 days. If it takes longer, we keep you informed. |
| Public disclosure | coordinated with you, normally once a fix is available, and no later than 90 days after your report |

Unless you prefer to stay anonymous, we credit you in the advisory. We do not run a paid bug bounty.

## Safe harbour

We will not take legal action against researchers who:

- act in good faith and follow this policy;
- test only their own installations or test environments, and **never scan networks they are not authorised to scan**;
- access, change or extract no more data than they need to demonstrate the issue;
- give us reasonable time to fix the issue before they disclose it.

## Scope

**In scope:**

- the source code in this repository
- the official release artefacts published under `github.com/59k-ai/cysec-scanner`

**Out of scope:**

- Third-party dependencies. Report those upstream, and please tell us too if cysec-scanner is affected.
- 59k's hosted services. Report those to the same address; they follow a separate process.

## Release integrity

Signed checksums and a CycloneDX software bill of materials (SBOM) for every release are planned. Until they ship, build from a tagged commit. Dependency licences are checked in CI (`go-licenses`), and reachable Go vulnerabilities are checked in CI (`govulncheck`).

## Regulatory note

59k GmbH handles vulnerabilities in line with the EU Cyber Resilience Act (Regulation (EU) 2024/2847). This includes coordinated vulnerability disclosure and reporting actively exploited vulnerabilities to the competent authorities.
