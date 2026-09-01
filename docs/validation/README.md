# Validation records

What has actually been run against a real machine, and what has not. Every record here binds to a
**commit** and to the **CI run that built it**, so a third party can check that the binary tested was
the binary that commit produces. A green count with no binding qualifies nothing - that lesson cost
this project a whole qualification cycle.

Start with [`VM_QUALIFICATION_KIT.md`](VM_QUALIFICATION_KIT.md) to reproduce any of these.

## Latest x64 campaign

| Scope | Result | Candidate | CI run | Record |
|---|---|---|---|---|
| Published v0.12.0 supply chain and x64 installer smoke | PASS: 6/6 checksums, 8/8 provenance/SBOM attestations, x64/Arm64 PE identity, x64 install/MCP/EN-FR-ES smoke/uninstall and zero residue | `b1c46ee` / tag `v0.12.0` | release `33497585184` PASS | [record](2026-09-01-v0.12.0-published-release.md) |
| v0.12.0 installer, WFP/SCM, trust, local/Network IPC, ETW recovery and final cleanup | PASS: 35/35 WFP, 13/13 trust, 7/7 local IPC, 7/7 Network Logon, 3/3 observer, ETW orphan/SCM/Ctrl+C recovery | `dbaded1` | CI `33416259797` + CodeQL `33416257089` PASS on the exact candidate | [record](2026-09-01-x64-qualification-dbaded1.md) |
| Dashboard settings layout, EN/FR/ES smoke, installer and Windows-security posture | PASS: exact ZIP/dashboard hashes, 4 equal 244 px buttons in 2-by-2 layout, centred local-analysis badge | `3912d67` | CI `32789592412` + CodeQL `32789591166` PASS on successor `8230aa9` | [record](2026-08-25-ui-windows-posture-3912d67.md) |
| ETW lifecycle, WFP/SCM, trust, local/Network IPC, installer and final cleanup | PASS: 19/19 ETW, 35/35 WFP, 13/13 trust, 7/7 local IPC, 7/7 Network Logon, 3/3 observer | `8486155` | CI `32664937545` + CodeQL `32664935397` PASS on successor `eed27a1`; local artifact hashes recorded | [record](2026-08-23-x64-qualification-8486155.md) |

The published-release record closes the checksum, attestation and x64 installer-smoke gate for the
actual v0.12.0 downloads. The `dbaded1` campaign is the current complete v0.12.0 native-x64
privileged-runtime qualification. The `3912d67`
record qualifies its earlier dashboard/package surface only; it deliberately does not
claim that privileged WFP/SCM gates were rerun. The `8486155` campaign exercised the current dynamic
WFP/SCM and ETW surfaces, exact protected-path trust,
local IPC and a real Network Logon from a second isolated VM. It retains harness-only red attempts
and binds the final green result to exact local artifact hashes. The previous partial campaign remains
historical rather than being silently overwritten.

## Closed on x64

| Gate | Result | Candidate | CI run | Record |
|---|---|---|---|---|
| WFP enforcement, SCM lifecycle, rollback, connectivity, per-app scoping | 25 checks, 0 failures | `f0a3f16` | `30024427883` | [record](2026-07-23-wfp-qualification-f0a3f16.md) |
| Service-path trust, adversarial TOCTOU / hostile ACLs | 11 checks, 0 failures | `f84ac36` | `30032903041` | [record](2026-07-23-trust-boundary-f84ac36.md) |
| Multi-user IPC capability boundary | 7 checks, 0 failures | `c9177cd` | `30046318762` | [record](2026-07-23-ipc-boundary-c9177cd.md) |

Each of these ran on a clean Windows 11 VM under Windows PowerShell 5.1, elevated, using the protocol
script shipped **inside the same package** as the binary under test, so the two cannot drift apart.
Each record qualifies only its named candidate. A later revision requires a candidate-aware delta
review of the relevant service, trust-boundary or IPC surface and a new run if that surface changed
or the impact is uncertain. These are qualification records for three exact x64 candidates, not
automatic inheritance or a product-wide production-readiness verdict.

## Superseded

[`2026-07-23-firewall-enforcement-x64.md`](2026-07-23-firewall-enforcement-x64.md) - an earlier
`18/18` transcript. Retained deliberately and marked invalid: the script revision behind it could
accept mixed WFP state, skip a failed probe, and observe a service bound to a different binary. It is
kept as a record of what that script printed, not as evidence.

## Not run

| Gate | Why |
|---|---|
| Native Arm64 privileged runtime | Native Arm64 CI build/package/installer passes, but WFP/SCM/trust/IPC/session needs an isolated Arm64 VM. See [`../ARM64_VALIDATION.md`](../ARM64_VALIDATION.md). |
| x64 emulated on Arm64 | Application-identity behavior has no x64-native equivalent and needs Arm64 hardware. |
| Signed Authenticode path | The current release policy is explicitly unsigned after SignPath Foundation declined the free application. A future certificate path remains unexercised. |
| Independent EN/FR/ES presentation | The project owner reviewed the French flow interactively through 2026-08-25; EN/ES have automated resource, minimum-width layout and VM smoke coverage, but no independent human attestation. |

Native x64 privileged-runtime and package qualification is established for v0.12.0 candidate
`dbaded1`; earlier runtime and UI records remain candidate-bound history.
Arm64-specific hardware gates remain open. Unsigned distribution has no Windows publisher identity
even when hashes and attestations verify.

## Why three of these records exist at all

Each of the three closed gates failed on its first real VM run, and in every case the defect was in
the **test harness**, not the product:

- the WFP protocol died at `0 checks` because `GetNewClosure()` captures variables but not functions,
  so every helper call inside the adapter threw when the script was launched with `&` instead of
  `-File`;
- the trust gate mis-read correct refusals, because Windows PowerShell 5.1 decorates native stderr and
  the script compared the whole decorated capture instead of the typed `[FW_...]` token - and its race
  copied user-writable *content* into a *protected* directory, then treated the correct trusted verdict
  as a bug;
- the IPC gate's restricted leg read its output file a beat too early, because `cmd`'s `>` creates the
  redirect target the instant the line starts.

The product was right every time. That is the point of running the gate on real hardware rather than
trusting a green count.
