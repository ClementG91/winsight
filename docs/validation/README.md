# Validation records

What has actually been run against a real machine, and what has not. Every record here binds to a
**commit** and to the **CI run that built it**, so a third party can check that the binary tested was
the binary that commit produces. A green count with no binding qualifies nothing — that lesson cost
this project a whole qualification cycle.

Start with [`VM_QUALIFICATION_KIT.md`](VM_QUALIFICATION_KIT.md) to reproduce any of these.

## Closed on x64

| Gate | Result | Candidate | CI run | Record |
|---|---|---|---|---|
| WFP enforcement, SCM lifecycle, rollback, connectivity, per-app scoping | 25 checks, 0 failures | `f0a3f16` | `30024427883` | [record](2026-07-23-wfp-qualification-f0a3f16.md) |
| Service-path trust, adversarial TOCTOU / hostile ACLs | 11 checks, 0 failures | `f84ac36` | `30032903041` | [record](2026-07-23-trust-boundary-f84ac36.md) |
| Multi-user IPC capability boundary | 7 checks, 0 failures | `c9177cd` | `30046318762` | [record](2026-07-23-ipc-boundary-c9177cd.md) |

Each of these ran on a clean Windows 11 VM under Windows PowerShell 5.1, elevated, using the protocol
script shipped **inside the same package** as the binary under test, so the two cannot drift apart.

## Superseded

[`2026-07-23-firewall-enforcement-x64.md`](2026-07-23-firewall-enforcement-x64.md) — an earlier
`18/18` transcript. Retained deliberately and marked invalid: the script revision behind it could
accept mixed WFP state, skip a failed probe, and observe a service bound to a different binary. It is
kept as a record of what that script printed, not as evidence.

## Not run

| Gate | Why |
|---|---|
| Native Arm64 | Needs Arm64 hardware. The x64 records prove x64 package behaviour only. See [`../ARM64_VALIDATION.md`](../ARM64_VALIDATION.md). |
| Foreign-owner-SID path trust | Needs a second standard account (`-HostileAccount`). The owner-trust path itself is proven by the TrustedInstaller leaf refusal. |
| Dedicated unelevated-admin and network-logon IPC | Covered by proxy (a SAFER basic-user token is the same non-admin capability class) and by the pipe DACL unit test, not by a live logon of each kind. |
| Installer, signing, deployment, release | Product decisions, not yet exercised end to end. |
| EN/FR/ES presentation | Needs human review of the localized surfaces. |

**Production readiness is not established.** These records close the largest gates on x64; they do not
close the list above.

## Why three of these records exist at all

Each of the three closed gates failed on its first real VM run, and in every case the defect was in
the **test harness**, not the product:

- the WFP protocol died at `0 checks` because `GetNewClosure()` captures variables but not functions,
  so every helper call inside the adapter threw when the script was launched with `&` instead of
  `-File`;
- the trust gate mis-read correct refusals, because Windows PowerShell 5.1 decorates native stderr and
  the script compared the whole decorated capture instead of the typed `[FW_...]` token — and its race
  copied user-writable *content* into a *protected* directory, then treated the correct trusted verdict
  as a bug;
- the IPC gate's restricted leg read its output file a beat too early, because `cmd`'s `>` creates the
  redirect target the instant the line starts.

The product was right every time. That is the point of running the gate on real hardware rather than
trusting a green count.
