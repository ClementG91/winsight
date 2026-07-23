# Service-path trust boundary — adversarial gate, candidate `f84ac36`

**Result: 11 checks, 0 failures, exit 0.**

The adversarial half of the trust boundary - hostile ACLs, a foreign owner, a reparse point, and a
live ACL-flip race - completed on a clean VM. This is the gate that had been `BLOCKED` since it was
written, because CI cannot build these filesystem states.

The first run of this gate on the VM failed five checks, all of them in the test harness (native
stderr decoration mistaken for the verdict, and a race that copied user-writable content into a
protected directory and was surprised it read trusted). Those were fixed in commit `f84ac36`; this is
the corrected gate, and the service was correct on every hostile state from the very first run.

## Candidate binding

| Field | Value |
|---|---|
| Candidate commit | `f84ac36a676484e745c14b8f61c8eb0dff30f5c8` |
| CI run that built it | `30032903041` (green, branch `main`) |
| Package | `winsight-win-x64`, deployed to `C:\Program Files\WinSight-VM` |
| Probe script | `Test-TrustBoundary.ps1`, shipped inside that package |
| Host | clean Windows VM (VirtualBox), Windows 11 build 26200, Windows PowerShell 5.1, elevated |
| Date | 2026-07-23 |
| Transcript | `C:\winsight-trust-boundary-f84ac36.txt` on the VM, reproduced below |

## What this establishes

The read-only `install-path-trust-check` verb - which shares Install's inspect-and-revalidate
primitive but can reach neither SCM nor WFP - returned the correct typed outcome for every state:

| State | Outcome |
|---|---|
| the protected candidate itself | `[FW_INSTALL_PATH_TRUSTED]`, exit 0 |
| a user-writable leaf | `[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]`, exit 1 |
| a missing path component | `[FW_INSTALL_PATH_MISSING_COMPONENT]`, exit 1 |
| a TrustedInstaller-owned leaf (a System32 exe) | `[FW_INSTALL_PATH_UNTRUSTED_OWNER]`, exit 1 |
| a copy in a protected root | `[FW_INSTALL_PATH_TRUSTED]`, exit 0 |
| a reparse point inside a protected root | `[FW_INSTALL_PATH_REPARSE_POINT]`, exit 1 |

The `UNTRUSTED_OWNER` refusal is correct by policy, not a bug: TrustedInstaller is a trusted owner for
parent directories but never for the leaf binary, which must be owned by SYSTEM or Administrators.

## The ACL-flip race

One honest file in the protected root, its ACL toggled between "an unprivileged principal
(`BUILTIN\Users`) can write" and "protected" on every iteration, probed in both states, 40 times:

- while user-writable: **never** trusted - every observation was
  `[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]`;
- while protected: trusted on every one of the 40 iterations.

Both properties held together, which is the point: the verdict tracks the file's real security state
and never lags into a stale trusted while it is writable. The second property is what stops the first
from passing for the boring reason that the probe refuses everything.

## Limitations of this record

- **The foreign-owner case was skipped.** It needs a second, non-administrator account passed as
  `-HostileAccount`. The owner-trust logic is still exercised - the TrustedInstaller-owned leaf is
  refused with `UNTRUSTED_OWNER` - but the "arbitrary standard-user owner" variant is unrun. Re-run
  with `-HostileAccount <standard user>` to close it; the count becomes 12.
- **The OS architecture was not captured.** The transcript header printed an empty value because
  `RuntimeInformation::OSArchitecture` returned nothing under 5.1, the same gap noted in the WFP
  qualification record. The package was `winsight-win-x64`, so this establishes x64 behaviour; it does
  not prove the host was native x64 rather than Arm64 under emulation. The kit prescribes
  `Win32_Processor` for future runs, which an emulated process cannot misreport.
- **This is the single-shot probe, not a concurrent in-inspection swap.** The verb's own
  inspect-and-revalidate closes the concurrent TOCTOU window; this gate proves the verdict is correct
  across rapid sequential state changes, and that no hostile state is ever reported trusted.

## Reproduce

```powershell
& 'C:\Program Files\WinSight-VM\Test-TrustBoundary.ps1' -ServicePath 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe'
```

Add `-HostileAccount <standard user>` to include the foreign-owner case.

## Transcript

```
== service-path trust boundary ==
  [PASS] console is elevated
  [PASS] candidate exists
  [PASS] the protected candidate is trusted
  [PASS] a user-writable leaf is refused
  [PASS] a missing path component is refused
  [PASS] a TrustedInstaller-owned leaf is refused
  [PASS] a copy in a protected root is trusted
  [PASS] a reparse point in a protected root is refused
  [SKIP] a foreign-owned leaf is refused: pass -HostileAccount <standard user> to run it
  [PASS] the user-writable leaf is never trusted across 40 ACL flips
  [PASS] the protected leaf still reads trusted across 40 ACL flips
         user-writable codes observed: [FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]
  [PASS] every hostile artefact is removed
Result: 11 checks, 0 failure(s).
```

Final exit code: **0**.
