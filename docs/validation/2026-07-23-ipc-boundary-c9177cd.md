# Multi-user IPC boundary — candidate `c9177cd`

**Result: 7 checks, 0 failures, exit 0.**

The authenticated firewall pipe grants the right capability per caller: an elevated administrator may
mutate policy, and an unprivileged caller may read status but is refused a mutation. This is the gate
that had no runnable end-to-end check until `winsight firewall-ipc-selftest` shipped, because only the
dashboard ever spoke to the pipe.

## Candidate binding

| Field | Value |
|---|---|
| Candidate commit | `c9177cdb681b8fbec676d142282e9475a3b5ae1d` |
| CI run that built it | `30046318762` (green, branch `main`) |
| Package | `winsight-win-x64`, deployed to `C:\Program Files\WinSight-VM` |
| Probe script + CLI | `Test-IpcBoundary.ps1` and `winsight.exe`, shipped inside that package |
| Host | clean Windows VM (VirtualBox), Windows 11 build 26200, Windows PowerShell 5.1, elevated |
| Architecture | x64 (operator-recorded) |
| Date | 2026-07-23 |
| Transcript | `C:\winsight-ipc-boundary-c9177cd.txt` on the VM, reproduced below |

## What this establishes

The self-test reports what the pipe grants the caller, over the real client the dashboard uses,
without changing machine state (its one mutation probe removes the policy for a path that is never a
real application, and is skipped when the machine is armed).

| Leg | Token | Outcome | Meaning |
|---|---|---|---|
| elevated | the administrator console | `CanMutate`, `mutation=Applied` | an elevated caller reads and mutates over the real pipe |
| restricted | a SAFER basic-user token via `runas /trustlevel`, password-free | `CanReadOnly`, `mutation=Unauthorized` | an unprivileged caller reads status but the mutation is refused before dispatch |

The restricted leg is the security-critical one. It proves that the pipe's DACL admits an unprivileged
interactive caller for reads (`serviceAvailable=true`) while the per-request capability check refuses
the policy mutation (`mutation=Unauthorized`). A restricted caller that could mutate, or that could
not even read, would be a defect; neither occurred.

## History of this gate on the VM

- First run: the restricted leg reported empty observations. Harness defect, not the service - `cmd`'s
  `>` created the output file the instant the command started, so the script read it before the
  diagnostic under the restricted token had written its line. Fixed in `c9177cd` with a DONE marker
  written only after the diagnostic exits.
- The elevated leg passed on both runs; the fix only affected how the restricted leg's output was
  read.

## Limitations of this record

- **The unelevated-administrator case is covered by proxy, not directly.** The restricted leg uses a
  SAFER basic-user token, which is non-administrator - the same capability class as an unelevated
  admin's filtered token (`IsInRole(Administrator)` is false for both). A dedicated unelevated-admin
  logon was not separately exercised.
- **The network-logon deny** (`\\host\pipe\...` from a remote session) is asserted by the pipe DACL
  unit test, not exercised here; this run is local only.
- **Architecture** is operator-recorded as x64; the package was `winsight-win-x64`. Native Arm64 is a
  separate gate.

## Reproduce

The service must be installed and running (pre-arm step 4.2 of the VM kit). Then:

```powershell
& 'C:\Program Files\WinSight-VM\Test-IpcBoundary.ps1'
```

## Transcript

```
== firewall IPC multi-user boundary ==
  [PASS] console is elevated
  [PASS] shipped CLI exists
  elevated:   [IPC_SELFTEST] outcome=CanMutate serviceAvailable=true mode=AuditOnly effectiveState=AuditOnly mutation=Applied
  [PASS] service is reachable from the elevated console
  [PASS] the elevated caller may mutate or reads an armed machine
  restricted: [IPC_SELFTEST] outcome=CanReadOnly serviceAvailable=true mode=AuditOnly effectiveState=AuditOnly mutation=Unauthorized
  [PASS] the unprivileged caller can still read status
  [PASS] the unprivileged caller is refused the mutation
  [PASS] the refused mutation reported Unauthorized
Result: 7 checks, 0 failure(s).
```

Final exit code: **0**.
