# x64 VM qualification — 2026-07-30

## Evidence identity

| Field | Value |
|---|---|
| Candidate | `3ad4b92d0b9a6ebc6ab0b99b082e2a0c4569f327` |
| CI run | `30536205557` |
| Platform | Windows 11, native x64 VM |
| Protocol | `docs/validation/VM_QUALIFICATION_KIT.md` as shipped by the candidate |
| Evidence location reported by operator | `Z:\WinSight-Evidence-3ad4b92` |
| Manifest | 46 entries |
| Manifest SHA-256 | `20e3b8f8651923f9b09dda1db7eeba5210726cba5651bbf1d9ea4bea97cc63e3` |

This record classifies the detailed result supplied by the VM operator. The sealed raw evidence
directory is not stored in this repository. Results are not promoted beyond the literal gates that
were reported and any workaround or missing prerequisite remains visible.

## Confirmed ETW correction

The campaign confirmed all of the following for the exact candidate:

- session names followed `WinSight-<Attribution|Outbound|DNS>-v2-<pid>-<16 hex>`;
- dashboard **X** kept the tray process and its session alive, which is the intended behavior;
- forced termination left an orphan;
- relaunch reclaimed the orphan while preserving another live dashboard's session;
- two additional kill/relaunch cycles never produced more sessions than live dashboards;
- tray Exit terminated the processes and left zero Attribution sessions;
- DNS kill/relaunch reclaimed the orphan, and Ctrl+C exited 0 and released the session;
- killing the Outbound service process left an orphan and the SCM restart reclaimed it under the new
  PID;
- zero `.NET Runtime` event 1026 occurred during the qualification window;
- the former `0x800705AA` resource-exhaustion crash was not reproduced.

Verdict for the ETW lifecycle defect: **PASS for this exact candidate**.

## Gate results

| Gate | Expected | Reported result | Classification |
|---|---|---|---|
| WFP contract self-test | 26/26, exit 0 | Conforming | PASS |
| WFP negative control | 26/1, exit 1 | Conforming | PASS |
| Pre-arm | 16/16, exit 0 | Conforming | PASS |
| Full WFP | 25/25, exit 0 | Conforming | PASS |
| Trust boundary | 12/12, no skip | Conforming | PASS |
| IPC elevated/restricted | 7/7, exit 0 | Passed only with explicit `-CliPath` | PASS_WITH_WORKAROUND |
| Network Logon | real Network token, exact command | Impersonation denial only | NOT_RUN |
| Installer | exit 0 | Conforming | PASS |
| `integrity --json` | exit 0 or 1, valid contract | exit 1, `notableCount=2` | PASS |
| Final cleanup | SCM 1060, WFP absent, control curl 200 | Conforming | PASS |
| Authenticode | policy-dependent | four targets `NotSigned` | EXPECTED_UNSIGNED |
| S0/S1/S2 take/restore | host-bound evidence | attempted from guest; `VBoxManage` absent | NOT_RUN |

## Defects found in the protocol

### IPC path drift

The package was protected under:

`C:\Program Files\WinSight-Qualification\payload`

but `Test-IpcBoundary.ps1` defaulted to:

`C:\Program Files\WinSight-VM\winsight.exe`

The script correctly failed closed with two checks and one failure. Supplying the protected CLI path
made the intended gate pass 7/7. The subsequent correction derives the CLI and service defaults from
`$PSScriptRoot` and also passes both paths explicitly from the runbook.

### Missing Network Logon method

Standard user, filtered administrator and elevated administrator behavior passed. A process created
locally with `LOGON32_LOGON_NETWORK` died before PowerShell because it lacked the interactive desktop.
Loopback WinRM was not a reliable substitute. Pipe denial was observed under impersonation with
Network SID `S-1-5-2` present and Interactive SID `S-1-5-4` absent, but this did not satisfy the
literal protocol and is correctly recorded as `NOT_RUN`.

The subsequent correction requires WinRM from a second isolated control machine and verifies the
token SIDs, exit 3, `ServiceUnavailable`, no mutation, and unchanged service PID/path.

### Snapshot authority mismatch

`VBoxManage` is a host tool and was absent from the guest. No S0/S1/S2 restore was therefore proved,
so snapshot continuity remains `NOT_RUN`. The subsequent correction labels all snapshot operations
host-only and requires externally hashed `showvminfo` records before guest work continues.

## Readiness conclusion

This campaign validates the ETW fix and the privileged x64 gates that actually ran. It does not prove
snapshot continuity, the exact Network Logon gate, native Arm64 privileged behavior, x64-on-Arm64
identity, or independent EN/FR/ES review. The later protocol corrections also need their own
candidate-bound CI artifact and VM rerun. Product readiness remains **not established**.
