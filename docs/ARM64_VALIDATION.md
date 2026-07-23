# Arm64 runtime validation (help wanted)

**Status: strict native qualification pending.** WinSight's outbound firewall has not passed the
current candidate-bound protocol on Arm64 Windows. The 2026-07-23 x64 transcript is historical
observation only, so corrected strict runs are pending on both x64 and native Arm64. This document
describes the Arm64 gate; it does not claim production qualification.

Explicit gate state: `NOT_RUN`/`BLOCKED` for the corrected x64 rerun, native Arm64, real SCM/WFP,
owner/DACL/nested-reparse/live-TOCTOU, connectivity and EN/FR/ES human presentation. Local tests and
the old x64 transcript cannot promote any of them.

## What CI already covers, and what it cannot

CI runs a native `windows-11-arm` runner, so this is **already automated** — please don't spend
time re-doing it:

- native Arm64 build of every project,
- the unit test suite (on tagged releases),
- the installer lifecycle: a real install and uninstall of the packaged Arm64 build.

What CI **cannot** cover is the part that actually filters traffic. The firewall reaches WFP
through P/Invoke into `fwpuclnt.dll`, and a hosted runner is not a place to cut network traffic
and watch what breaks. Everything below is about that.

## Why Arm64 could genuinely differ

This is not box-ticking. The plausible failure modes are specific:

- **Struct layout and marshalling.** The WFP interop passes native structs by pointer
  (`FWPM_FILTER0`, `FWPM_FILTER_CONDITION0`, `FWP_CONDITION_VALUE0`, `FWP_BYTE_BLOB`). Different
  alignment or packing on Arm64 surfaces as a wrong `FWP_E_*` code, a filter that installs but
  never matches, or a silent no-op — not as a crash.
- **App-id derivation.** `FwpmGetAppIdFromFileName0` produces the identity every block is keyed
  on. If it yields a different blob on Arm64, filters install and match nothing.
- **Emulated x64 processes.** Arm64 Windows runs x64 binaries under emulation. Whether an
  emulated x64 process's app id matches the on-disk path the same way a native Arm64 process's
  does is **unknown, and is the single most interesting question here.** Step 5 records why that
  separate protected-target gate remains blocked; this procedure does not execute an unqualified
  user-writable x64 copy.

## Before you start

- **Use a VM with a clean snapshot.** Step 3 really does cut network traffic for one process.
  Emergency disable is intended to restore it, but uninstall is forbidden unless AuditOnly, the
  exact empty WFP tuple and restored connectivity are all proven. Any failed rollback requires
  snapshot recovery.
- You need an **elevated** console. The service installs to a trusted path, and the dashboard
  must be elevated to arm the machine — both are enforced, not conventions.
- Build from `main`, or grab the `winsight-win-arm64` artifact from CI.

## Getting a build, and checking it is the one we published

Validating an artifact you have not verified proves something about a file, not about WinSight. Every
release carries a SHA-256 and a **build provenance attestation**, so both are worth the thirty
seconds — and a security tool asking you to skip that check would be a poor advertisement for itself.

Nothing below needs anything Windows does not already ship. **Do not assume the GitHub CLI is
present** — a validation VM is a clean machine, which is the entire point of using one, and an early
draft of this section opened with `gh release download` and failed on the first line for exactly that
reason.

```powershell
# Set the version once. Use -win-arm64 in place of -win-x64 on Arm hardware.
$version = "<candidate-tag>"
$name    = "winsight-$version-win-arm64.zip"
$base    = "https://github.com/ClementG91/winsight/releases/download/$version"

New-Item -ItemType Directory -Force C:\winsight-dl | Out-Null

# curl.exe has shipped with Windows since 10 1803 and is the fastest thing here.
curl.exe -sSL -o "C:\winsight-dl\$name"        "$base/$name"
curl.exe -sSL -o "C:\winsight-dl\$name.sha256" "$base/$name.sha256"

# Checksum: the published digest must match the file you actually have.
$expected = (Get-Content "C:\winsight-dl\$name.sha256").Split(' ')[0].Trim()
$actual   = (Get-FileHash "C:\winsight-dl\$name" -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "checksum mismatch" } else { "checksum OK" }
```

**If you use `Invoke-WebRequest` instead, silence the progress bar first.** Windows PowerShell 5.1 —
which is what a clean VM opens by default — redraws that bar on every chunk received, and on a
170 MB archive the rendering, not the network, becomes the bottleneck. Measured on this release:
**4 seconds** with the bar silenced against minutes with it on, for byte-identical output.

```powershell
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest "$base/$name" -OutFile "C:\winsight-dl\$name" -UseBasicParsing
```

**What that check is and is not worth.** It proves the file matches the digest published beside it —
which is enough to catch a truncated download or a corrupted mirror, and not enough to catch anyone
who could replace both. Build provenance is the check that fails a supply-chain attack, because it
proves GitHub Actions built the artifact from this repository. It needs the GitHub CLI, which is one
line to install and entirely reasonable on a VM you are about to discard:

```powershell
winget install --id GitHub.cli --silent --accept-source-agreements --accept-package-agreements
gh attestation verify "C:\winsight-dl\$name" --repo ClementG91/winsight
```

The eligible candidate archive must ship `Test-WfpValidation.ps1` beside the executables it
validates. An older archive without that script cannot satisfy the strict gate: do not fetch a
different revision from `main` and combine it with those binaries.

Then extract and deploy into a trusted location. **This step needs an elevated console** — writing
under `Program Files` requires it, and the copy fails per-file with `UnauthorizedAccessException` if
it is not, which reads as a broken command rather than a missing privilege. That the location is
privileged is the point: the service refuses to install from anywhere an unprivileged user can write,
and step 1 of the protocol exercises that refusal deliberately.

```powershell
Expand-Archive "C:\winsight-dl\$name" -DestinationPath C:\winsight-stage -Force
New-Item -ItemType Directory -Force -Path 'C:\Program Files\WinSight-VM' | Out-Null
Copy-Item C:\winsight-stage\* 'C:\Program Files\WinSight-VM\' -Recurse -Force
$svc = 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe'
$protocol = 'C:\Program Files\WinSight-VM\Test-WfpValidation.ps1'
```

The strict run executes that deployed `$protocol` from the same protected candidate directory as
`$svc`; a download/staging copy elsewhere is not the evidence producer.

Building from source instead is fine and covered in step 0 below; the published artifact is preferred
because it is what a user actually runs.

## Run it as a script, not by hand

`scripts/Test-WfpValidation.ps1` executes this protocol and prints a verdict per step. Prefer it to
the manual walkthrough below — a validation nobody can replay is indistinguishable, six months later,
from one that was never run, and a transcript with `[PASS]`/`[FAIL]` lines is replayable where a
recollection is not.

```powershell
$svc = 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe'
$protocol = 'C:\Program Files\WinSight-VM\Test-WfpValidation.ps1'

# VM-only pre-arm qualification. It does not arm WFP, but it installs, starts, stops and
# uninstalls the candidate service and verifies SCM absence before success.
& $protocol -ServicePath $svc -SkipEnforcement

# full protocol, including real traffic blocking. Take a VM snapshot first.
& $protocol -ServicePath $svc
```

If PowerShell refuses to run it — a downloaded script is blocked by default, which is correct
behaviour and not a fault — unblock that one file rather than weakening the machine's policy:

```powershell
Unblock-File $protocol
```

`-SkipEnforcement` is not a machine-read-only mode; it is safe only inside the isolated VM protocol
and must complete its SCM cleanup. The full path cannot reach its manual arming prompt after any
failed pre-arm check or failed connectivity baseline.

Run `& $protocol -ContractSelfTest` without `-ServicePath` for the final normal non-privileged
**24/24** contract check. Then run
`& $protocol -ContractSelfTest -ContractNegativeControl`; that deliberate lifecycle-order negative
control must exit **1**. The former 14/14 and the first local report based on it are invalid,
non-qualifying evidence. The intermediate 15/15 was a transient development count and is not proof.
The VM skip/full paths retain exactly **16**/**25** mandatory checks.

One `New-ValidationAdapter` owns native command construction, staging, workflow operations and the
Running, Stopped and SCM-absent polls. Real and scripted modes inject only elementary host effects;
the scripted mode consumes a closed exact ordered queue and fails on an unexpected path, argument,
order, cardinality or result type. It exposes no fake `PollRunning`, `PollStopped`, `PollAbsent` or
other business outcome. Delayed/timeout matrices traverse the same production adapter for all three
polls, preserve exact ten-attempt bounds and prove uninstall remains unreachable before Stopped.
Strict typed cardinality requires effects to return zero success objects and decisions exactly one
value of the expected type.

The protected candidate's CLI has one public `FirewallServiceCommandHost.Execute` route for parsing,
routing, arity, result mapping and stdout/stderr. `Program` constructs the Windows capabilities and
calls it exactly once. The path-probe handler receives only `IServicePathTrustInspector`, directly
uses the shared inspect/revalidate primitive and has no install or SCM/WFP capability. Tests traverse
that public route, while a non-privileged invalid-arity subprocess smoke traverses the real `Program`
root and requires exact inspection-failed stderr/exit 1 without inspection or machine mutation.
These portable checks do not replace this Arm64 VM protocol. Cleanup still polls bounded
locale-invariant Running, Stopped and absent states, and rollback failure makes uninstall
unreachable.

The full protocol pauses at the two steps that cannot be automated — arming and emergency disable — because
mutating policy requires authenticated IPC by design, and the command-line verbs for it are refused
on purpose. It tells you exactly what to click, then verifies the result. It is architecture-agnostic:
everything below applies to x64 too, and step 5 is the only Arm64-specific part.

The manual protocol is kept below because it explains *why* each step exists. It cannot replace the
candidate-bound script transcript or turn a partial run into qualification evidence.

## The protocol

### 0. Deploy

```powershell
$proj = ".\src\WinSight.FirewallService\WinSight.FirewallService.csproj"
dotnet publish $proj -c Release -r win-arm64 --self-contained true -o C:\winsight-stage
New-Item -ItemType Directory -Force -Path 'C:\Program Files\WinSight-VM' | Out-Null
Copy-Item C:\winsight-stage\* 'C:\Program Files\WinSight-VM\' -Recurse -Force
$svc = 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe'
$windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$sc = Join-Path $windows 'System32\sc.exe'
$target = Join-Path $windows 'System32\curl.exe'
$control = Join-Path $windows 'System32\WindowsPowerShell\v1.0\powershell.exe'
```

The operator must establish the protected candidate as a trust root before using it: verify its
provenance, deploy it to the protected location and keep its dependencies immutable. The
candidate's own path probe does not prove those prerequisites, and no ProgramData-only restriction
is inferred for the executable. Every elevated OS tool below uses the absolute protected path just
defined; ambient `PATH` is never consulted.

### 1. Service lifecycle and path trust

```powershell
& $svc install                       # expect: Installed 'WinSight Firewall'
& $sc qc WinSightFirewall | Select-String BINARY_PATH_NAME
& $sc start WinSightFirewall
# Poll Win32_Service.State for exact `Running`, at most 10 attempts.
& $svc enforce-status
# exact output:
# Persisted desired enforcement mode: AuditOnly. Effective runtime state: unknown (query the authenticated running service).
```

For both status forms, the normative interpretation is `effective runtime unknown`: the persisted
desired mode is known, but the authenticated running service must be queried for current runtime
state.

Then confirm that user-writable data is refused. Create only a sentinel and ask the protected
candidate to inspect it; never copy, execute or load a service executable or DLL from this staging
directory:

```powershell
$probeDirectory = Join-Path $env:USERPROFILE ('Desktop\winsight-path-trust-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $probeDirectory | Out-Null
$sentinel = Join-Path $probeDirectory 'user-writable-sentinel.exe'
New-Item -ItemType File -Path $sentinel | Out-Null
& $svc install-path-trust-check $sentinel   # expect: one [FW_INSTALL_PATH_*] code, exit 1
Remove-Item -LiteralPath $probeDirectory -Recurse -Force
```

Accepted path-denial outputs are the fixed allowlist:
`[FW_INSTALL_PATH_INVALID]`, `[FW_INSTALL_PATH_OUTSIDE_MACHINE_DATA]`,
`[FW_INSTALL_PATH_MISSING_COMPONENT]`, `[FW_INSTALL_PATH_REPARSE_POINT]`,
`[FW_INSTALL_PATH_UNTRUSTED_OWNER]`, `[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]`,
`[FW_INSTALL_PATH_IDENTITY_CHANGED]` and `[FW_INSTALL_PATH_INSPECTION_FAILED]`. The generic
`[FW_INSTALL_FAILED]` means an unrelated install/SCM failure and does not satisfy this path probe.

### 2. WFP engine, read-only

```powershell
& $svc wfp-selftest
# exact shape, exit 0:
# WFP engine opened. Existing filters visible: <non-negative integer>. Read-only: no filter, provider or sublayer was added or changed.

& $svc wfp-block-add $target   # exact [FW_DIRECT_MUTATION_DISABLED], exit 1
& $svc wfp-status
# exact post-refusal inventory, exit 0:
# WinSight WFP provider: absent, sublayer: absent, permit-filter: absent. Per-app blocks are queried with wfp-block-status <path>.
```

**Stop here and report** if the engine will not open, or if `wfp-selftest` reports an `FWP_E_*`
error. That is the interop-difference signal and it is worth more than the rest of the protocol.

### 3. Real enforcement, native Arm64 target

Use protected System32 `curl.exe` as the native Arm64 target, never a user-writable copy and never
`ping.exe` — ping sends ICMP via the IP Helper service, so an app-id filter never matches it and you
would be measuring nothing. Use protected Windows PowerShell as a separate HTTP control.

```powershell
& $target -s -o NUL -w '%{http_code}' --max-time 20 https://example.com
# expect exact 200, exit 0
& $control -NoProfile -NonInteractive -Command "try { `$r = Invoke-WebRequest -UseBasicParsing -Uri 'https://example.com' -TimeoutSec 20; [Console]::Out.Write([int]`$r.StatusCode); exit 0 } catch { [Console]::Out.Write('000'); exit 2 }"
# expect exact 200, exit 0
```

Now, in an **elevated** dashboard: *Outbound firewall* → *Start analysis* → *Block an app…* →
the absolute path in `$target` → then *Enable enforcement* and confirm.

```powershell
& $svc enforce-status
# exact output, exit 0:
# Persisted desired enforcement mode: Enforcement. Effective runtime state: unknown (query the authenticated running service).
& $svc wfp-status
# exact output, exit 0:
# WinSight WFP provider: present, sublayer: present, permit-filter: absent. Per-app blocks are queried with wfp-block-status <path>.
& $svc wfp-block-status $target   # exact [FW_APP_BLOCKED], exit 0

# blocked target -> exact 000 and non-zero exit
& $target -s -o NUL -w '%{http_code}' --max-time 20 https://example.com
# independent control -> exact 200 and exit 0
& $control -NoProfile -NonInteractive -Command "try { `$r = Invoke-WebRequest -UseBasicParsing -Uri 'https://example.com' -TimeoutSec 20; [Console]::Out.Write([int]`$r.StatusCode); exit 0 } catch { [Console]::Out.Write('000'); exit 2 }"
```

The control leg matters as much as the blocked target: if both fail, the filter is not app-scoped
and that is a bug.

### 4. Rollback

Dashboard → *Emergency disable*.

```powershell
& $svc enforce-status
# exact AuditOnly status shape shown in step 1, exit 0
& $svc wfp-status
# exact absent/absent/absent inventory shown in step 2, exit 0
& $target -s -o NUL -w '%{http_code}' --max-time 20 https://example.com
# exact 200, exit 0
& $control -NoProfile -NonInteractive -Command "try { `$r = Invoke-WebRequest -UseBasicParsing -Uri 'https://example.com' -TimeoutSec 20; [Console]::Out.Write([int]`$r.StatusCode); exit 0 } catch { [Console]::Out.Write('000'); exit 2 }"
# exact 200, exit 0
```

### 5. Emulated x64 target — the Arm64-specific question

This gate remains `NOT_RUN`/`BLOCKED`. Do not download, copy or execute an x64 target from a
user-writable directory for this procedure. A future emulation gate needs a separately
provenance-checked target deployed with immutable dependencies to an operator-protected location,
then candidate-bound and exercised with the same target/control and rollback invariants as step 3.

**Does `FwpmGetAppIdFromFileName0` key the filter such that an emulated x64 process is blocked?**
Whatever the answer, it is worth reporting — a "no" is a genuine finding, not a failed test.

### 6. Clean up

Do not run uninstall until step 4 has proven AuditOnly, the exact absent provider/sublayer/permit
tuple and restored target connectivity. If any proof fails, leave the recovery service registered
and restore the clean snapshot.

```powershell
& $sc stop WinSightFirewall
# Poll Win32_Service.State for exact `Stopped`, at most 10 attempts.
& $svc uninstall
# Poll `& $sc query WinSightFirewall` for error 1060 (absent), at most 10 attempts.
```

Then restore the snapshot.

## What to report

Please open an issue (or comment on the tracking one) with:

1. Windows build (`winver`) and the machine (e.g. Surface Pro X, Dev Kit 2023, Snapdragon X).
2. The complete displayed console transcript of steps 1–5. Native output remains visible with its
   exit code but is normalized: `ErrorRecord` becomes its message, `Out-String` collects it, then
   display trims and prefixes each line. This is not the original native byte stream.
3. For any refusal, the exact fixed `[FW_INSTALL_PATH_*]`, `[FW_DIRECT_MUTATION_DISABLED]` or
   `FWP_E_*` code. Generic `[FW_INSTALL_FAILED]` is not a successful path-trust probe.
4. Step 5's `NOT_RUN`/`BLOCKED` state and the missing protected x64-target prerequisite; do not
   substitute a user-writable copied executable.
5. Anything that surprised you. On x64, all three of the defects fixed in #61, #62 and #63 were
   invisible to the unit tests and only showed up against a real machine. Assume the same here.

A partial report is worth far more than none: even "step 2 fails with `FWP_E_...`" closes a real
question. Thank you.
