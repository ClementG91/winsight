# Security Policy

WinSight is a security tool, so we take the security of the project itself seriously.

## Supported versions

The project is pre-1.0 and under active development. Security fixes are applied to
the latest `main` and the most recent tagged release.

| Version | Supported |
| ------- | --------- |
| latest `main` | ✅ |
| latest release | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab → **Report a vulnerability**
   (GitHub Private Vulnerability Reporting).
2. Provide a description, affected component, reproduction steps, and impact.

We aim to acknowledge reports within **72 hours** and to provide a remediation
timeline after triage. Please give us reasonable time to fix an issue before any
public disclosure. We will credit reporters who wish to be acknowledged.

## Scope

In scope: all WinSight libraries, CLI, dashboard, packaging scripts, installers and
GitHub release workflows. Of particular interest:

- Signature-verification bypass (a tampered binary reported as trusted).
- Privilege or path-handling issues in the scanners.
- Unsafe dashboard actions or execution of attacker-controlled finding data.
- Installer privilege escalation, architecture confusion, unsafe upgrade/uninstall
  behavior, or release-provenance/SBOM inconsistencies.
- Any scanner code path that unexpectedly modifies user state (analysis is intended
  to be read-only).

Third-party dependency vulnerabilities should normally be reported upstream, but a
WinSight-specific exploitable integration remains in scope. Public release binaries
currently lack Authenticode signing because the project does not own a public
code-signing certificate; checksum or SmartScreen warnings caused solely by that
documented limitation are not vulnerabilities. Integrity is currently supplied by
SHA-256 files, GitHub build-provenance/SBOM attestations, and signed Git commits and
tags.
