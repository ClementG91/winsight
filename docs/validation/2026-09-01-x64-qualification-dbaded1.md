# x64 CI candidate qualification - 2026-09-01

**Result: PASS for the native-x64 v0.12.0 CI candidate at `dbaded1`.**

This record is bound to commit `dbaded1feac9803d4fa3ffd122036b176ab6d47c`, CI run
`33416259797`, and the exact x64 artifacts below. It does not qualify privileged Arm64 behavior or
future release artifacts with different bytes.

## Candidate identity

| Item | SHA-256 |
|---|---|
| `winsight-v0.12.0-win-x64.zip` | `B2CE342231F3EE777D41D5BEDECC28C78B4F57D0AAB1549D5C978DE8F6A7894A` |
| `winsight-v0.12.0-win-x64-setup.exe` | `F0FE9614A076069020E825D186C0E2DA710B38E7A7BB5A95613D37D8A339228E` |
| `winsight-v0.12.0-win-x64.spdx.json` | `F05081598B45D7B2614A113E6DAC27BC3B5D0F9F76EE0855B1C3B76A35B181EF` |
| protected candidate manifest | `5DAD4E24D1C02E5D9AABCB34AFBF18489E5174E32DDF1905A094932B8A17AF12` |

The clean S0 bootstrap and installer lifecycle passed twice from the same externally recorded S0
state. Both runs reported native x64/AMD64 execution and the expected accepted unsigned-distribution
posture. The protected source stayed clean at the candidate commit throughout the campaign.

## Privileged and multi-user gates

| Gate | Result |
|---|---|
| WFP contract | 26/26 |
| WFP negative control | expected 26 checks, 1 failure, exit 1 |
| pre-arm cleanup | 17/17; service query ended at 1060 |
| full WFP/SCM transition and rollback | 35/35; service query ended at 1060 |
| path, ACL and TOCTOU trust boundary | 13/13, using a real standard hostile account |
| local elevated/restricted IPC | 7/7; `CanMutate` / `CanReadOnly` |
| real remote Network Logon IPC | 7/7 |
| independent elevated target observer | 3/3; PID and protected service path unchanged |

The Network Logon leg used a separate Windows 11 control VM over a host-only network. WinRM was
exposed only through a temporary HTTPS listener, Basic authentication was used only inside TLS, and
the inbound rule admitted only the control VM address. The temporary account belonged only to
`Users` and `Remote Management Users`. Its token contained `S-1-5-2` (Network) and excluded
`S-1-5-4` (Interactive). It could not open the authenticated pipe, received
`ServiceUnavailable`, returned the current CLI contract code 11, and performed no mutation.
`LocalAccountTokenFilterPolicy` remained absent; no `TrustedHosts` or unencrypted WinRM bypass was
used.

The first evaluation exposed validation drift rather than a product failure: the shipped diagnostic
correctly returned code 11, while `Test-IpcBoundary.ps1` still expected the pre-contract code 3.
The raw 7-check transcript and independent 3-check observer were retained and re-evaluated against
the central `CliContract.ServiceUnavailable` value. Their SHA-256 values are respectively
`300C8FBC3CFDC4BFA8168B436679E32473F63D9F83A7C2E4CE7B13A52C2B5391` and
`2BB2971C16395BB00ABB741D07D3176B1D6EDFD3BD8F4A80D4DC0A63AA8EF25C`.
The corrected harness hash is
`7EF81CFE95BCB63DFECE9D9F6584BF967BDAD88259F86DA58E699E9DEA242B65`.

A later retry that stalled in an installer process after SCM registration was classified as an
invalid harness attempt, preserved separately, and never counted as evidence. The final S1 restore
discarded its state.

## ETW and UI lifecycle

The exact candidate passed the dashboard close-to-tray and tray-exit lifecycle, three forced-kill
orphan-recovery cycles, outbound-service SCM automatic recovery, and DNS Ctrl+C shutdown using a
real `GenerateConsoleCtrlEvent(CTRL_C_EVENT)`. Outbound recovery replaced PID 8868 with PID 9096;
DNS recovery replaced PID 1560 with PID 2928. Both legs observed and recovered the orphaned ETW
session, recorded zero `.NET Runtime` crash events, and ended with no WinSight ETW session. The
outbound leg also retained `AuditOnly`, an empty WFP namespace, working IPC, HTTPS 200, and final SCM
absence (1060).

## Final state and CI

The target was restored to protected snapshot
`S1-dbaded1-final-candidate-protected` (`5bb942b6-8bdf-42d0-b7c8-34673262e243`). A final
non-elevated independent check found the service absent (1060), no WinSight ETW session, and HTTPS
200. The snapshot's already-qualified elevated state is `AuditOnly` with an empty WFP namespace.

CI run `33416259797` passed on Windows 2022 x64, Windows 2025 x64 and native Windows 11 Arm64,
including formatting, dependency audit, build, coverage, CFA/ETW contracts, both native installer
packages, and the aggregate gate. CodeQL run `33416257089`, GitGuardian and the external review gate
also passed. Local follow-up verification after correcting the validation drift passed 2,619/2,619
Release tests, strict formatting, a zero-warning Release build, and the NuGet vulnerability audit.

## Scope limits

- Authenticode remains deliberately unavailable under the documented unsigned-release policy.
- Native Arm64 build, tests, packaging and installer lifecycle passed in CI. Privileged Arm64
  WFP/SCM/trust/IPC/session behavior remains `NOT_RUN` until suitable isolated hardware is
  available.
- x64-on-Arm64 application-identity behavior remains `NOT_RUN` for the same hardware reason.
- Published v0.12.0 release assets require their own checksum, provenance, installer and smoke
  verification; this record qualifies the CI candidate, not bytes that have not yet been published.
