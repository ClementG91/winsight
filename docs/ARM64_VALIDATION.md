# Arm64 runtime validation (help wanted)

**Status: unvalidated.** WinSight's outbound firewall has never been exercised at runtime on
Arm64 Windows. We have no Arm64 hardware. This document is the protocol; if you have an Arm64
Windows machine and ~30 minutes, you can close a real gap for this project.

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
  does is **unknown, and is the single most interesting question here.** Step 5 covers it.

## Before you start

- **Use a VM with a clean snapshot.** Step 3 really does cut network traffic for one process.
  Everything is reversible (there is an emergency disable, and uninstalling removes all WFP
  state), but a snapshot means you never have to trust that.
- You need an **elevated** console. The service installs to a trusted path, and the dashboard
  must be elevated to arm the machine — both are enforced, not conventions.
- Build from `main`, or grab the `winsight-win-arm64` artifact from CI.

## Run it as a script, not by hand

`scripts/Test-WfpValidation.ps1` executes this protocol and prints a verdict per step. Prefer it to
the manual walkthrough below — a validation nobody can replay is indistinguishable, six months later,
from one that was never run, and a transcript with `[PASS]`/`[FAIL]` lines is replayable where a
recollection is not.

```powershell
# read-only half: preconditions, service lifecycle, path trust, WFP probe. Arms nothing.
./scripts/Test-WfpValidation.ps1 -ServicePath 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe' -SkipEnforcement

# full protocol, including real traffic blocking. Take a VM snapshot first.
./scripts/Test-WfpValidation.ps1 -ServicePath 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe'
```

It pauses at the two steps that cannot be automated — arming and emergency disable — because
mutating policy requires authenticated IPC by design, and the command-line verbs for it are refused
on purpose. It tells you exactly what to click, then verifies the result. It is architecture-agnostic:
everything below applies to x64 too, and step 5 is the only Arm64-specific part.

The manual protocol is kept below because it explains *why* each step exists, which a script cannot.

## The protocol

### 0. Deploy

```powershell
$proj = ".\src\WinSight.FirewallService\WinSight.FirewallService.csproj"
dotnet publish $proj -c Release -r win-arm64 --self-contained true -o C:\winsight-stage
New-Item -ItemType Directory -Force -Path 'C:\Program Files\WinSight-VM' | Out-Null
Copy-Item C:\winsight-stage\* 'C:\Program Files\WinSight-VM\' -Recurse -Force
$svc = 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe'
```

### 1. Service lifecycle and path trust

```powershell
& $svc install                       # expect: Installed 'WinSight Firewall'
sc.exe qc WinSightFirewall | Select-String BINARY_PATH_NAME
sc.exe start WinSightFirewall ; Start-Sleep 5
sc.exe query WinSightFirewall        # expect: STATE : 4 RUNNING
& $svc enforce-status                # expect: persisted desired AuditOnly; effective runtime unknown
```

Then confirm a user-writable path is refused — this is the path-trust boundary:

```powershell
$bad = "$env:USERPROFILE\Desktop\wsvc"
New-Item -ItemType Directory -Force -Path $bad | Out-Null
Copy-Item C:\winsight-stage\* "$bad\" -Recurse -Force
& "$bad\winsight-firewall-service.exe" install   # expect: [FW_INSTALL_FAILED], exit 1
```

### 2. WFP engine, read-only

```powershell
& $svc wfp-selftest    # expect: engine opened, a filter count, nothing added or changed
& $svc wfp-status      # expect: provider: absent, sublayer: absent
```

**Stop here and report** if the engine will not open, or if `wfp-selftest` reports an `FWP_E_*`
error. That is the interop-difference signal and it is worth more than the rest of the protocol.

### 3. Real enforcement, native Arm64 target

Use a **copy** of `curl.exe`, never `ping.exe` — ping sends ICMP via the IP Helper service, so an
app-id filter never matches it and you would be measuring nothing.

```powershell
New-Item -ItemType Directory -Force -Path C:\curltest | Out-Null
Copy-Item C:\Windows\System32\curl.exe C:\curltest\ -Force
C:\curltest\curl.exe -s -o NUL -w "%{http_code}`n" --max-time 15 https://example.com   # expect 200
```

Now, in an **elevated** dashboard: *Outbound firewall* → *Start analysis* → *Block an app…* →
`C:\curltest\curl.exe` → then *Enable enforcement* and confirm.

```powershell
& $svc enforce-status                          # expect: persisted desired Enforcement; effective runtime unknown
& $svc wfp-status                              # expect: provider: present, sublayer: present
& $svc wfp-block-status C:\curltest\curl.exe   # expect: [FW_APP_BLOCKED]

# blocked target -> must FAIL
C:\curltest\curl.exe -s -o NUL -w "http=%{http_code}`n" --max-time 20 https://example.com
# unblocked System32 copy -> must still SUCCEED (proves per-app scoping, not a global cut)
C:\Windows\System32\curl.exe -s -o NUL -w "http=%{http_code}`n" --max-time 20 https://example.com
```

On x64 this yields `http=000` (exit 2) for the blocked copy and `http=200` (exit 0) for the
unblocked one. **The unblocked leg matters as much as the blocked one**: if both fail, the filter
is not app-scoped and that is a bug.

### 4. Rollback

Dashboard → *Emergency disable*.

```powershell
& $svc enforce-status   # expect: persisted desired AuditOnly; effective runtime unknown
& $svc wfp-status       # expect: provider: absent, sublayer: absent  (WFP state cleaned up)
C:\curltest\curl.exe -s -o NUL -w "http=%{http_code}`n" --max-time 20 https://example.com  # expect 200
```

### 5. Emulated x64 target — the Arm64-specific question

This step has no x64 equivalent and is the reason this document exists. Take an **x64** build of
curl (from curl.se, or copy `curl.exe` off an x64 machine), put it in `C:\curltest-x64\`, confirm
it runs, then block it and enable enforcement exactly as in step 3.

**Does `FwpmGetAppIdFromFileName0` key the filter such that an emulated x64 process is blocked?**
Whatever the answer, it is worth reporting — a "no" is a genuine finding, not a failed test.

### 6. Clean up

```powershell
sc.exe stop WinSightFirewall ; & $svc uninstall
sc.exe query WinSightFirewall   # expect 1060 (absent) = clean uninstall
```

Then restore the snapshot.

## What to report

Please open an issue (or comment on the tracking one) with:

1. Windows build (`winver`) and the machine (e.g. Surface Pro X, Dev Kit 2023, Snapdragon X).
2. **Raw console output** of steps 1–5. Paste it verbatim; a summary loses the codes that matter.
3. For any refusal, the **exact code**: `[FW_INSTALL_FAILED]`, `[FW_DIRECT_MUTATION_DISABLED]`,
   `UntrustedOwner`, `WritableByUnprivilegedPrincipal`, `OutsideProgramData`, `ReparsePoint`,
   `IdentityChanged`, or an `FWP_E_*` value.
4. Step 5's answer, whichever way it goes.
5. Anything that surprised you. On x64, all three of the defects fixed in #61, #62 and #63 were
   invisible to the unit tests and only showed up against a real machine. Assume the same here.

A partial report is worth far more than none: even "step 2 fails with `FWP_E_...`" closes a real
question. Thank you.
