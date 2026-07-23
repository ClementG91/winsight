# WFP qualification — corrected strict protocol, candidate `f0a3f16`

**Result: 25 checks, 0 failures, exit 0.**

This is the first run of the corrected, candidate-bound protocol to complete. It supersedes the
[historical `18/18` transcript](2026-07-23-firewall-enforcement-x64.md), which remains invalid as
strict evidence and is kept only as a record of what the older script printed.

## Candidate binding

| Field | Value |
|---|---|
| Candidate commit | `f0a3f16d982c4b687b53caeb314f2ce505fa5e91` |
| CI run that built it | `30024427883` (green) |
| Package | `winsight-win-x64`, deployed to `C:\Program Files\WinSight-VM` |
| Protocol script | the copy shipped **inside** that package, built from the same commit |
| Host | clean Windows VM (VirtualBox), Windows 11 build 26200, Windows PowerShell 5.1, elevated |
| Date | 2026-07-23 |
| Transcript | `C:\winsight-run-f0a3f16.txt` on the VM, reproduced in full below |

The binding is the point. The previous qualification attempt was invalidated because nothing tied the
observed behaviour to a known binary; this run states the commit, the CI run that produced it, and
uses the protocol script that travelled in the same package.

## What this establishes

**Real SCM lifecycle, end to end.** Clean snapshot proven empty (`1060`), install, SCM registration
bound to the canonical candidate plus the `run` verb, start, Running, stop, Stopped, uninstall, and
`1060` again. No step was inferred; each has its own check.

**Path trust, with the exact reason.** The protected candidate refused a user-writable sentinel with
`[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]` — the specific typed code, not a generic failure. The
sentinel was staged as data only and never executed or loaded.

**WFP read-only inspection.** The engine opened with 573 existing filters visible and changed
nothing. Before arming, the inventory was exactly `provider: absent, sublayer: absent,
permit-filter: absent`.

**Direct mutation is refused, and the refusal is proven inert.** `wfp-block-add` returned
`[FW_DIRECT_MUTATION_DISABLED]` with exit 1, and the immediately following inventory still read
absent/absent/absent. The refusal did not quietly half-apply anything.

**Armed state is exact.** After arming through the dashboard and authenticated IPC:
`provider: present, sublayer: present, permit-filter: absent`.

**The block is scoped to one application.** This is the single most important line in the run:

| Probe | Before arming | While armed | After rollback |
|---|---|---|---|
| System32 `curl.exe` (the blocked target) | 200, exit 0 | **000, exit 7** | 200, exit 0 |
| Windows PowerShell HTTP (independent control) | 200, exit 0 | **200, exit 0** | 200, exit 0 |

Both legs matter. Had the control also failed, the "block" would have been a machine-wide cut wearing
a per-app label — a defect, not a success.

**Rollback is complete.** Back to `AuditOnly`, all WFP state removed (absent/absent/absent), and both
the target and the control restored to 200.

Both elevated pauses were driven through the real dashboard over authenticated IPC. That is not a gap
in the harness: mutating policy has no command-line path by design, which is the security property
itself.

## Limitations of this record

- **The OS architecture was not captured.** The transcript header printed an empty value because
  `[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture` returned nothing in that
  session. The package deployed was `winsight-win-x64`, so this establishes x64 **package**
  behaviour; it does not by itself prove the host was native x64 rather than Arm64 running x64 under
  emulation. `VM_QUALIFICATION_KIT.md` now prescribes a command that reports OS/CPU architecture from
  `Win32_Processor`, which an emulated process cannot misreport.
- **Native Arm64 is not covered.** Emulated-x64 app-id behaviour and Arm64 struct marshalling remain
  open. See [`ARM64_VALIDATION.md`](../ARM64_VALIDATION.md).
- **The adversarial TOCTOU race is not exercised here.** Hostile ACL/owner/reparse and
  rename-aside-then-plant races against service-path trust are a separate, narrower validation.
- **Multi-user IPC token classification** needs a second, non-administrator account and was not run.
- **Installer, signing, deployment and release** gates were not run.
- **EN/FR/ES human presentation review** was not run.

Production readiness is not established by this run alone. What it does close is the largest
previously-open gate, on x64, with a binding a third party can check.

## Reproduce

Follow [`VM_QUALIFICATION_KIT.md`](VM_QUALIFICATION_KIT.md). In short, on an isolated VM snapshot:

```powershell
gh api repos/ClementG91/winsight/actions/runs/30024427883 --jq '.head_sha, .conclusion'
& 'C:\Program Files\WinSight-VM\Test-WfpValidation.ps1' -ContractSelfTest
& 'C:\Program Files\WinSight-VM\Test-WfpValidation.ps1' -ContractSelfTest -ContractNegativeControl
& 'C:\Program Files\WinSight-VM\Test-WfpValidation.ps1' -ServicePath 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe' -SkipEnforcement
& 'C:\Program Files\WinSight-VM\Test-WfpValidation.ps1' -ServicePath 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe'
```

## Transcript

```
== WFP validation protocol ==
  [PASS] console is elevated
  [PASS] candidate and protected tools exist
  [PASS] user-writable sentinel is staged as data
  > sc.exe query WinSightFirewall (exit 1060)
    [SC] EnumQueryServicesStatus:OpenService echec(s) 1060 :
    Le service specifie n'existe pas en tant que service installe.
  [PASS] clean snapshot has no WinSight service
  > winsight-firewall-service.exe install (exit 0)
    Installed 'WinSight Firewall' (demand-start; enforcement is opt-in and runtime state is reported separately).
    Start it with:  sc start WinSightFirewall
  [PASS] candidate install succeeds
  [PASS] SCM binds the canonical candidate and run verb
  > sc.exe start WinSightFirewall (exit 0)
    SERVICE_NAME: WinSightFirewall
            TYPE               : 10  WIN32_OWN_PROCESS
            STATE              : 2  START_PENDING
            PID                : 8260
  [PASS] service starts and reaches Running
  > winsight-firewall-service.exe enforce-status (exit 0)
    Persisted desired enforcement mode: AuditOnly. Effective runtime state: unknown (query the authenticated running service).
  [PASS] starts in audit-only
  > winsight-firewall-service.exe install-path-trust-check C:\Users\vboxuser\Desktop\winsight-path-trust-<guid>\user-writable-sentinel.exe (exit 1)
    [FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]
  [PASS] protected candidate refuses the sentinel path
  > winsight-firewall-service.exe wfp-selftest (exit 0)
    WFP engine opened. Existing filters visible: 573. Read-only: no filter, provider or sublayer was added or changed.
  [PASS] WFP engine opens
  > winsight-firewall-service.exe wfp-status (exit 0)
    WinSight WFP provider: absent, sublayer: absent, permit-filter: absent. Per-app blocks are queried with wfp-block-status <path>.
  [PASS] no WFP state before arming
  > winsight-firewall-service.exe wfp-block-add C:\WINDOWS\System32\curl.exe (exit 1)
    [FW_DIRECT_MUTATION_DISABLED]
  > winsight-firewall-service.exe wfp-status (exit 0)
    WinSight WFP provider: absent, sublayer: absent, permit-filter: absent. Per-app blocks are queried with wfp-block-status <path>.
  [PASS] direct mutation is refused without changing WFP
  > curl.exe -s -o NUL -w %{http_code} --max-time 20 https://example.com (exit 0)
    200
  > powershell.exe -NoProfile -NonInteractive -Command <Invoke-WebRequest example.com> (exit 0)
    200
  [PASS] target and control reach the network before blocking
  > winsight-firewall-service.exe enforce-status (exit 0)
    Persisted desired enforcement mode: Enforcement. Effective runtime state: unknown (query the authenticated running service).
  [PASS] enforcement is persisted
  > winsight-firewall-service.exe wfp-status (exit 0)
    WinSight WFP provider: present, sublayer: present, permit-filter: absent. Per-app blocks are queried with wfp-block-status <path>.
  [PASS] WFP state is exactly armed
  > winsight-firewall-service.exe wfp-block-status C:\WINDOWS\System32\curl.exe (exit 0)
    [FW_APP_BLOCKED]
  [PASS] the System32 curl target reads as blocked
  > curl.exe -s -o NUL -w %{http_code} --max-time 20 https://example.com (exit 7)
    000
  [PASS] blocked System32 curl cannot reach the network
  > powershell.exe -NoProfile -NonInteractive -Command <Invoke-WebRequest example.com> (exit 0)
    200
  [PASS] PowerShell HTTP control still reaches the network
  > winsight-firewall-service.exe enforce-status (exit 0)
    Persisted desired enforcement mode: AuditOnly. Effective runtime state: unknown (query the authenticated running service).
  > winsight-firewall-service.exe wfp-status (exit 0)
    WinSight WFP provider: absent, sublayer: absent, permit-filter: absent. Per-app blocks are queried with wfp-block-status <path>.
  > curl.exe -s -o NUL -w %{http_code} --max-time 20 https://example.com (exit 0)
    200
  > powershell.exe -NoProfile -NonInteractive -Command <Invoke-WebRequest example.com> (exit 0)
    200
  [PASS] back to audit-only
  [PASS] all WFP state is removed
  [PASS] target and control connectivity are restored
  > sc.exe stop WinSightFirewall (exit 0)
    SERVICE_NAME: WinSightFirewall
            STATE              : 3  STOP_PENDING
  [PASS] service stop succeeds
  [PASS] service reaches stopped state before uninstall
  > winsight-firewall-service.exe uninstall (exit 0)
    Removed 'WinSight Firewall'.
  [PASS] candidate uninstall succeeds
  > sc.exe query WinSightFirewall (exit 1060)
    [SC] EnumQueryServicesStatus:OpenService echec(s) 1060 :
    Le service specifie n'existe pas en tant que service installe.
  [PASS] uninstall leaves no service
Result: 25 checks, 0 failure(s). full validation cleanup complete
```

Final exit code: **0**.

Non-ASCII characters in the localized `sc.exe` output above were transliterated so this file stays
ASCII; the exit codes and check lines are verbatim.
