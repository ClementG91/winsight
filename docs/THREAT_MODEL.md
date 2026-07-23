# Threat model

What WinSight protects, from whom, and — just as importantly — what it does not. Every claim here
points at code or at a validation record; nothing is aspirational.

## What WinSight is

A local, telemetry-free Windows security suite: read-only scanners for triage, plus an **opt-in**
per-application outbound firewall built on the Windows Filtering Platform.

It is a **visibility and triage tool**, not antivirus and not an EDR. A notable finding is evidence to
investigate, not proof of compromise.

## Assets

| Asset | Why it matters |
|---|---|
| The machine's outbound network policy | WinSight can cut a real application's traffic |
| The policy store (`%ProgramData%\WinSight`) | Determines what gets filtered |
| The LocalSystem service and its SCM registration | Runs as the most privileged account on the box |
| The named-pipe control channel | The only route to mutating policy |
| The truthfulness of the reported state | An operator acts on "filtered" or "not filtered" |
| Released binaries | Users run them with Administrator rights |

The last two deserve emphasis. For a security tool, **lying about its own state is a security
failure**, not a cosmetic one, and it is treated as such throughout the codebase and the test suite.

## Trust boundaries

```
   unprivileged user session                 |   LocalSystem
                                             |
   dashboard (WPF)  ─┐                       |
   winsight.exe CLI ─┼─► named pipe ═════════╪══► firewall service
                     │   authenticated       |    ├─ policy store (ACL-protected)
   MCP client ───────┘   capability-gated    |    └─ WFP engine
                                             |
   ─────────────────────────────────────────────────────────────
   filesystem: service binary must live where no unprivileged
   principal can write it (verified before SCM registration
   AND re-verified before use)
```

**The privileged boundary is the pipe, not the UI.** The dashboard is an ordinary unprivileged client.
It cannot change policy by itself; it asks, and the service decides based on the caller's Windows
token.

### Capability model

The service impersonates each caller (`RunAsClient`) and classifies the real token:

| Caller | Capability | Can read status | Can mutate policy |
|---|---|---|---|
| SYSTEM | `MutateMachinePolicy` | yes | yes |
| Elevated administrator | `MutateMachinePolicy` | yes | yes |
| Unelevated administrator (filtered token) | `ReadStatus` | yes | **no** |
| Standard user | `ReadStatus` | yes | **no** |
| Network logon | `None` | **no** | **no** |
| Anonymous / guest / unauthenticated | `None` | **no** | **no** |

Enforced at two independent layers: the pipe ACL (SYSTEM and Administrators full, Interactive
read/write, **Network denied**) and a per-request capability check that refuses a mutation before it
is dispatched.

Verified end to end on real hardware — an unprivileged token reads status and is refused the mutation:
[`docs/validation/2026-07-23-ipc-boundary-c9177cd.md`](validation/2026-07-23-ipc-boundary-c9177cd.md).

## Adversaries considered

### 1. Unprivileged local user

*Goal: change firewall policy, or unblock their own application.*

Defeated by the capability model above. The pipe is reachable (an interactive user must be able to
read status for the dashboard to work) but mutation is refused before dispatch.

### 2. Local user planting a binary

*Goal: get the LocalSystem service to execute code they control.*

Before registering the service, and again before using the inspected path, WinSight verifies every
component of the path: it must exist, contain no reparse point, be owned by SYSTEM or Administrators
(TrustedInstaller is accepted for parent directories but never for the binary itself), and grant no
dangerous write to an unprivileged principal. Failures return one of eight typed codes, never a
generic error.

The inspect-then-use race is closed by binding the decision to the file's 128-bit NTFS identity
(`FILE_ID_INFO`) and re-validating it before use, so a file swapped between the two moments is
rejected as `IDENTITY_CHANGED`.

Verified against real hostile filesystem states, including a 40-iteration ACL-flip race:
[`docs/validation/2026-07-23-trust-boundary-f84ac36.md`](validation/2026-07-23-trust-boundary-f84ac36.md).

### 3. Remote attacker

*Goal: reach the control channel over the network.*

The pipe carries an explicit **deny** ACE for the Network SID, and the capability classifier
independently returns `None` for any identity holding it. Denies take precedence over allows, so
group membership cannot route around it. WinSight opens no listening socket.

### 4. Tampered download

*Goal: get a user to install a modified build.*

SHA-256 per asset, an SPDX SBOM, and GitHub build-provenance attestations bound to the workflow,
repository and commit. Checksums are generated in the build job and **re-verified in a separate job**
after artifacts move. Authenticode is implemented and awaiting a certificate.

### 5. Corrupted or tampered policy store

*Goal: make the machine filter the wrong things, or believe it is protected when it is not.*

The store lives under an ACL-protected machine-data root whose trust is checked before every read and
write. A corrupt, oversized, truncated, unknown-schema or future-schema file **recovers to audit-only
with a diagnostic** rather than being partially honoured — deliberately failing towards "not
filtering" rather than cutting a machine off the network on a parse error.

The runtime state is re-verified against the live WFP engine on every status read; anything short of
exact verification downgrades to `Degraded` in a `finally`, so `Active` can never be reported without
live proof.

## Explicitly out of scope

| Not defended | Why |
|---|---|
| An adversary already running as SYSTEM | They outrank every control WinSight has |
| Kernel-mode malware, rootkits, hypervisor attacks | No driver; user-mode only |
| Physical access, DMA, offline disk tampering | Outside a user-mode tool's reach |
| Detection evasion by malware | WinSight is triage, not EDR — a missed technique is a coverage gap |
| Malicious Windows updates or a compromised OS | WinSight trusts the platform it runs on |
| A compromised GitHub account or signing key | Provenance proves which workflow built it, not that the workflow was trustworthy |

WinSight deliberately ships **no kernel driver**. Driver-backed features in the Objective-See
equivalents (BlockBlock, RansomWhere) are deferred rather than half-built, because a production driver
needs signing and a separate safety programme.

## Privacy

No telemetry, no analytics, no automatic network calls. The single outbound connection is a
VirusTotal hash lookup, which is explicit, user-initiated, rate-limited, and sends a hash — never file
contents. Executable paths are preserved verbatim in reports as forensic evidence and are not
transmitted anywhere.

## Residual risk

- **Native Arm64 privileged behaviour is unqualified.** The x64 gates are closed with reproducible
  records; Arm64 has native CI coverage for build, PE architecture, installer lifecycle and smoke
  tests, but WFP/SCM/TOCTOU/IPC on Arm64 need an elevated native VM. See
  [`docs/PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).
- **Released binaries are unsigned** until a code-signing certificate exists.
- The service must be deployed to a protected location by an administrator. WinSight verifies this and
  refuses otherwise, but it cannot create the trust root for you.
