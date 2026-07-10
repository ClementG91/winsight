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

In scope: the WinSight tool libraries and CLI (persistence, camera/mic, connections,
signature verification, reporting). Of particular interest:

- Signature-verification bypass (a tampered binary reported as trusted).
- Privilege or path-handling issues in the scanners.
- Any code path that could modify user state (WinSight is intended to be read-only).

Out of scope: issues in third-party dependencies (report upstream), and the inherent
limitation that the current signature check relies on `Get-AuthenticodeSignature`
(the native `WTGetSignatureInfo` path is tracked).
