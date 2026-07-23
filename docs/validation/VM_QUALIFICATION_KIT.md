# VM qualification kit

Everything CI cannot reach lives here. The firewall's enforcement path goes through WFP by P/Invoke
and cuts real traffic, and the service runs as LocalSystem, so the only honest way to qualify it is
to install it on a machine you are willing to break.

> [!CAUTION]
> **Run this on an isolated virtual machine only. Never on a working PC.**
> The full protocol installs a SYSTEM service, arms the Windows Filtering Platform and blocks real
> network traffic for a real process. Everything is reversible by design, but a VM snapshot means
> never having to trust that sentence.

## 1. Bind the candidate before anything else

The single defect that invalidated the previous qualification run was that nothing tied the observed
behaviour to a known candidate. A protocol that qualifies "whatever service happens to be installed"
qualifies nothing. So the first step is not a download, it is a binding.

| Field | Value |
|---|---|
| Candidate commit | `f0a3f16d982c4b687b53caeb314f2ce505fa5e91` |
| CI run that built it | `30024427883` |
| Artifacts | `winsight-win-x64`, `winsight-win-arm64` |

> [!IMPORTANT]
> **Do not reuse a package fetched before this commit.** Earlier candidates carry a defect that kills
> the protocol on its first output call, printing
> `Result: 0 checks, 1 failure(s). output operation violated the zero-output contract`. If you see
> that, the package is stale - re-fetch, do not debug it.

> [!WARNING]
> **The file name lies about the version.** `Directory.Build.props` still reads `0.10.3`, so the
> artifact unpacks as `winsight-v0.10.3-win-x64`. It is **not** the released `v0.10.3` tag - it is a
> CI build of a later commit. Never identify this candidate by its file name. Identify it by the CI
> run's `head_sha`, checked below.

Prove the run built the commit you think it did, from any machine:

```powershell
gh api repos/ClementG91/winsight/actions/runs/30024427883 --jq '.head_sha, .conclusion'
```

It must print `f0a3f16d982c4b687b53caeb314f2ce505fa5e91` and `success`. If it does not, stop; you are
about to qualify something else.

## 2. Prepare a clean VM

Take a snapshot **now**, before installing anything. You will want to roll back to it.

A clean Windows VM has no `gh`, and the default shell is Windows PowerShell 5.1, not PowerShell 7.
Both of those have bitten this protocol before.

```powershell
winget install --id GitHub.cli --source winget --accept-package-agreements --accept-source-agreements
```

Close and reopen the console so `gh` lands on `PATH`, then authenticate:

```powershell
gh auth login --hostname github.com --git-protocol https --web
```

> [!NOTE]
> **If a download appears to hang, it is the progress bar.** Windows PowerShell 5.1 renders
> `Invoke-WebRequest` progress synchronously, which can turn a 120 MB download into several minutes
> of apparent freeze. Set `$ProgressPreference = 'SilentlyContinue'` for the session, or use
> `curl.exe` from System32, which does not have the problem.

## 3. Fetch the exact candidate

```powershell
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force C:\winsight-dl | Out-Null
gh run download 30024427883 --repo ClementG91/winsight -n winsight-win-x64 -D C:\winsight-dl
```

On a native Arm64 VM, substitute `-n winsight-win-arm64`. Do not run the x64 package on Arm64 and
call it an Arm64 result: emulated-x64 app-id behaviour and Arm64 struct marshalling are exactly what
that gate exists to test.

Verify the package against the checksum shipped beside it, then unpack:

```powershell
Get-ChildItem C:\winsight-dl -Filter *.sha256 | ForEach-Object { Get-Content $_.FullName }
Get-FileHash C:\winsight-dl\winsight-v0.10.3-win-x64.zip -Algorithm SHA256 | Format-List
```

```powershell
Expand-Archive C:\winsight-dl\winsight-v0.10.3-win-x64.zip -DestinationPath C:\winsight-stage -Force
```

Deploy to a protected, non-user-writable location. The service refuses to install from a
user-writable path, and that refusal is itself one of the checks:

```powershell
New-Item -ItemType Directory -Force 'C:\Program Files\WinSight-VM' | Out-Null
Copy-Item C:\winsight-stage\winsight-v0.10.3-win-x64\* 'C:\Program Files\WinSight-VM' -Recurse -Force
```

The protocol script travels **inside** the package. Use that copy, not one downloaded separately from
`main`: it was built from the same commit as the binary, so the two cannot drift apart.

## 4. Run the gates, in order

Each gate is a real gate. A later one is meaningless if an earlier one failed.

### 4.1 Contract self-test (non-privileged, no machine changes)

```powershell
& 'C:\Program Files\WinSight-VM\Test-WfpValidation.ps1' -ContractSelfTest
```

Expect `[CONTRACT-SELFTEST PASS] 24 checks` and exit 0.

Then the negative control, which proves the contract can actually fail:

```powershell
& 'C:\Program Files\WinSight-VM\Test-WfpValidation.ps1' -ContractSelfTest -ContractNegativeControl
```

Expect `24 checks, 1 failures` and **exit 1**. A negative control that passes is a broken contract,
not a good sign.

### 4.2 Pre-arm lifecycle (elevated, SCM only, no WFP)

Open an **elevated** console. This installs, starts, stops and removes the service. It does not arm
enforcement and does not touch WFP.

```powershell
& 'C:\Program Files\WinSight-VM\Test-WfpValidation.ps1' -ServicePath 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe' -SkipEnforcement
```

Expect exactly **16 checks, 0 failures**. `-SkipEnforcement` is not a read-only mode: it changes the
machine and then must prove it cleaned up, including SCM error 1060 after uninstall.

### 4.3 Full protocol (elevated, arms WFP, cuts real traffic)

Snapshot again first. This one blocks real network traffic.

```powershell
& 'C:\Program Files\WinSight-VM\Test-WfpValidation.ps1' -ServicePath 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe'
```

Expect exactly **25 checks, 0 failures**.

The run pauses twice and asks you to act in the dashboard. That is deliberate and cannot be
automated: mutating policy requires authenticated IPC, so there is no command-line path to it. That
is the security property, not a gap in the harness.

- **First pause** - in an **elevated** dashboard: Outbound firewall -> Start analysis, then
  Block an app -> `C:\Windows\System32\curl.exe`, then Enable enforcement -> confirm.
- **Second pause** - dashboard -> Emergency disable.

The single most important line in the output is `an unblocked copy still reaches the network`. It
proves the block is scoped to one application rather than being a machine-wide cut. If the blocked
leg passes while that line fails, the result is a **defect**, not a success.

### 4.4 Service-path trust boundary (elevated, read-only probe, no SCM and no WFP)

This is the adversarial half. It builds hostile filesystem states that CI cannot create - foreign
owners, reparse points, a user-writable plant - and drives the candidate's read-only
`install-path-trust-check` verb against each. Nothing here installs, starts or stops a service, and
nothing touches WFP.

```powershell
& 'C:\Program Files\WinSight-VM\Test-TrustBoundary.ps1' -ServicePath 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe'
```

Add `-HostileAccount <standard user>` to include the foreign-owner case; without it that one case is
reported as skipped rather than silently dropped.

Two results look like defects and are not:

- **A System32 executable is refused** with `[FW_INSTALL_PATH_UNTRUSTED_OWNER]`. TrustedInstaller is a
  trusted owner for parent directories but never for the leaf binary, which must be owned by SYSTEM or
  Administrators. That is the policy, deliberately.
- **A junction resolves to its target**, so a junction inside a user-writable tree reports
  `WRITABLE_BY_UNPRIVILEGED`, not `REPARSE_POINT`. Only a reparse point whose resolved chain is
  otherwise trusted can surface `REPARSE_POINT`, which is why the script builds one inside a protected
  root.

The race section renames the trusted file aside and plants a user-writable one at the same path, then
probes, then restores - repeatedly. Two properties must hold together: the planted file is **never**
reported trusted, and the honest file still reads trusted every time. The second is what stops the
first from passing for the boring reason that the probe refuses everything.

Codes that had not been measured before this gate existed are **recorded rather than asserted**, and
the script prints which typed code fired. Tighten those to exact codes in a follow-up once the first
run has recorded them; do not tighten them to a code you have not seen.

## 5. Record the result

A run nobody can replay is a story. Capture the full transcript:

```powershell
& 'C:\Program Files\WinSight-VM\Test-WfpValidation.ps1' -ServicePath 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe' *>&1 | Tee-Object C:\winsight-run.txt
```

Record the architecture with this, **not** with `RuntimeInformation::OSArchitecture` - that returned
an empty string on a real 5.1 session and silently left the architecture out of a run's record:

```powershell
$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Architecture
$osArch = switch ($cpu) { 0 {'x86'} 5 {'ARM'} 9 {'x64'} 12 {'ARM64'} default {"unknown($cpu)"} }
Write-Host "OS/CPU architecture : $osArch"
Write-Host "PowerShell process  : $env:PROCESSOR_ARCHITECTURE"
```

> [!WARNING]
> **`$env:PROCESSOR_ARCHITECTURE` alone cannot satisfy the Arm64 gate.** An x64 process running under
> emulation on an Arm64 machine reports `AMD64`, so a run that records only the process architecture
> can look like native x64 when it is not. `Win32_Processor` reports the real CPU (`12` = ARM64) and
> an emulated process cannot misreport it. For the Arm64 gate the OS/CPU line must read `ARM64` and
> the package must be `winsight-win-arm64`.

A result is only qualifying evidence if it records all of: the candidate commit, the CI run id, the
architecture, whether the VM was clean, the exact check counts, and every failure. Add it to
`docs/validation/` beside this file - see
[`2026-07-23-wfp-qualification-f0a3f16.md`](2026-07-23-wfp-qualification-f0a3f16.md) for the shape.
If any gate failed, record that too - an honest red transcript is worth more than a green one nobody
can reproduce.

## 6. What these gates do and do not close

Passing every gate above closes: real SCM lifecycle, real WFP provisioning and teardown, per-app
scoping, connectivity before/during/after, and the path-trust install refusal, on the architecture
you ran.

It does **not** close:

- the other architecture - x64 and native Arm64 are separate gates;
- the adversarial TOCTOU race on service-path trust (hostile ACL/owner/reparse/rename-aside races),
  which is a separate, narrower validation;
- multi-user IPC token classification, which needs a second, non-administrator account;
- installer, signing, deployment and release;
- EN/FR/ES human presentation review.

Until those are recorded too, `production_ready` stays **false**. Green counts on this page are
evidence about what was measured, not a claim about what was not.
