# Hyper-V qualification harness

The host side of WinSight's disposable-VM qualification (`docs/validation/VM_QUALIFICATION_KIT.md`),
kept in the repository so that what runs elevated on the host, and what runs in the guest, is
reviewed like any other code and can be bound to a commit.

The host installs the protected qualification harness and manages two disposable Hyper-V VMs,
their transport disks and a private switch. Product enforcement tests run inside the guests;
the harness does not manipulate the development workstation's WinSight, WFP or product services.
The network gate authenticates from the control guest to the target guest's private HTTPS WinRM
endpoint using a disposable non-administrator account. Privileged host staging, collection and
checkpoint recovery require the independently authenticated owner-installed harness.

## Trust boundary (RA-01)

The first version kept its scripts, the staged candidate, the VM disks and the evidence at the root of
a data volume, where Authenticated Users have Modify by inheritance, and its elevated runner wrote,
moved and deleted files there. Hashes of that evidence proved it was consistent, not that nobody had
changed a script before a run or a result after it. Now:

| Location | Who can write | What the runner does there |
|---|---|---|
| `<vol>\WinSight-Qualification-Requests` | the requesting user | reads request files (≤ 4 KB), never writes, moves or deletes; reads `candidates\<name>` when asked to stage it |
| `<protected-installation>` | administrators (users read) | runner and verifier installed by the independently authenticated launcher |
| `<vol>\WinSight-Qualification\harness\<stamp>` | administrators | the harness copied from the protected installation, re-hashed before every action |
| `<vol>\WinSight-Qualification\candidates\<id>` | administrators | a candidate copied file by file on a `stage` request, re-hashed before every action |
| `<vol>\WinSight-Qualification\sealed` | administrators (users read) | manifests, host log, one new directory per run |
| `<vol>\WinSight-Qualification\runner` | administrators (users read) | status, log, action logs, processed request names |
| `<vol>\Hyper-V\WinSight-Qualification` | administrators, Hyper-V | refused unless already protected |

`<vol>` is the root of the volume the scripts run from: every default location above derives from
it, and each script takes the path as a parameter to use another.

Rules every elevated script here follows: write only into a directory it created with an
administrators-only DACL, or one it has just verified; read from user-writable places only an explicit
list of files, refusing reparse points; never delete recursively (Windows PowerShell 5.1
`Remove-Item -Recurse` follows junctions). The data disk the guest writes to is emptied by formatting
it, and results come back file by file without entering a link, because the guest runs the candidate
as an administrator.

RB-01: **never elevate a script from the checkout.** Earlier instructions did this before creating
the protected copies. A changed entry point could run first, then copy reviewed bytes, leaving all
11 post-run checks green. The runner's comment containing its own blob could not authenticate its
execution. Historical passes retain that limitation; their evidence is never rewritten.

The current entry path is a self-contained release launcher containing the exact committed harness
bytes, including the verifier. An independently trusted SHA-256 authenticates the complete launcher
in memory before any of its code runs. The same buffer is executed, so no checked pathname is
reopened. It creates an admin-owned installation, verifies the complete file inventory, and records
the external launcher digest and commit in `bootstrap-provenance.json`. The runner copies only from
that protected installation and carries its receipt into each run. The verifier, also run from the
protected installation, requires the operator's external digest and rejects missing receipts,
partial manifests/artifact sets, or an unsuccessful identity gate (RB-04).

The byte-substitution, manifest and generation tests run unelevated under Windows PowerShell 5.1.
Actual elevated installation, pre-launch substitution trials and new VM passes remain operator
acceptance gates; implementing this path does not retroactively authenticate old runs.

## Authenticate and install the harness (operator only)

1. From an independently trusted review context, verify the release launcher's GitHub build
   attestation against the repository, release workflow, tag and source commit, and obtain its
   SHA-256 from that verified attestation. The asset is
   `winsight-v<version>-qualification.ps1`; its `.sha256` alone, read beside a mutable local file,
   is not a trust anchor. The reviewed source commit and the operator-pasted entry code are also
   part of this trust decision. Local development launchers can be generated unelevated with
   `New-TrustedQualificationLauncher.ps1 -Commit <40-hex-commit> -OutputPath <new-file.ps1>`;
   authenticate their digest in an independent trusted context before using them.
2. Open a fresh elevated **Windows PowerShell 5.1**, using the system executable with `-NoProfile`.
   Copy the two functions from the independently reviewed immutable source of
   `Invoke-VerifiedQualificationLauncher.ps1` into that console. **Do not use `-File`, dot-source,
   or import the checkout's copy.** The functions download only the named HTTPS release asset,
   enforce a size bound, hash it and execute exactly the verified byte buffer.
3. In that console, install to a new local path whose parent already exists, for example:

   ```powershell
   Install-WinSightTrustedHarness `
       -LauncherUri 'https://github.com/ClementG91/winsight/releases/download/v<version>/winsight-v<version>-qualification.ps1' `
       -ExpectedSha256 '<digest from the independently verified attestation>' `
       -Destination 'D:\WinSight-TrustedHarness-<commit>'
   ```

   Existing destinations are refused. Files and directories, including their ancestors, must be
   protected against replacement by ordinary users. Only this protected installation may supply
   elevated scripts or the verifier. Use explicit paths below when qualification data is on a
   different volume from the installation.

## Once

1. From the protected installation, build the VMs (`New-WinSightHyperVVm.ps1`, then the runner's
   `control` request for the second VM), passing the intended data-volume paths.
2. Protect their storage with the protected `Protect-WinSightVmStorage.ps1`. It seals the disk hashes in
   `<vol>\WinSight-Qualification\sealed\vm-storage-<stamp>.txt`. A VM whose disks sat in a folder any
   user could modify is only as trustworthy as that folder was; rebuilding it into protected storage is
   what removes the doubt about the past.

## Each campaign

1. After authentication and installation above, start the protected runner in the operator console:
   `& '<protected-installation>\WinSightQualRunner.ps1' -Root '<vol>\WinSight-Qualification' -Requests '<vol>\WinSight-Qualification-Requests' -VmRoot '<vol>\Hyper-V\WinSight-Qualification'`.
   It refuses a writable installation, missing bootstrap receipt, changed bytes, or unsafe VM storage.
2. For final PR qualification, obtain the exact successful CI x64 artifact and verify its run/head,
   packaging checkout tree and artifact digest. Put its unchanged setup/ZIP/SBOM in `out/release`
   under a clean checkout of that source revision, then assemble unelevated with
   `New-QualificationCandidate.ps1 -BuildTree <checkout> -Name <name> -PreviousInstaller <published setup>
   -PreviousSha256 <its published hash> -PreviousCommit <its commit>`: the artifacts, the repository's
   `scripts` at that commit, the published installer the upgrade gate starts from, and
   `candidate.json` binding them by SHA-256, in `<vol>\WinSight-Qualification-Requests\candidates\<name>`.
3. Queue requests as JSON files with unique names in `<vol>\WinSight-Qualification-Requests`:
   `{"action":"stage","candidate":"<name>"}`, then `{"action":"qualify","runName":"...","gates":[...],"memoryGB":4}`,
   `{"action":"network","runName":"...","memoryGB":3,"credentialMode":"automatic"}` for gate 36
   with a freshly generated disposable password staged on both protected offline guest volumes.
   No password belongs in the request. The fixed account is not an administrator; the colocated AES
   key/cipher rely on the Administrators/System-only volume DACL, not secrecy from administrators.
   Each guest consumes/removes its fixture and host recovery attempts cleanup on both disks and
   both checkpoints. Omitting `credentialMode`, or selecting `"interactive"`, retains the operator
   dialog in each VM. Other values are rejected. Use the newly authenticated 14-file installation;
   the older 13-file harness does not implement automatic mode.
   The control VM runs with 2 GB, and the run is refused up front if the host
   cannot hold both VMs plus 0.5 GB), `{"action":"stop"}` at the end. Progress: `<vol>\WinSight-Qualification\runner\status.json` and
   `runner.log` beside it. Use short snapshot reads; do not follow logs or block on the driver.
   Parent runner heartbeat and actual child PID/phase/UTC heartbeat are separate; stale child data
   does not prove progress or authorize extending a watchdog.
4. Verify each run as an ordinary user, from the protected installation, before citing it:
   `& '<protected-installation>\Verify-QualificationProvenance.ps1' -RunDir '<vol>\WinSight-Qualification\sealed\<run>' -HarnessCommit <sha> -LauncherSha256 <independently-trusted-digest> -Repository <reviewed-checkout> -Root '<vol>\WinSight-Qualification' -VmRoot '<vol>\Hyper-V\WinSight-Qualification'`.
   Every check must print PASS: the seal, the harness blob ids against the reviewed commit, the
   authenticated bootstrap, complete candidate scripts against the candidate's commit, the full
   artifact triplet and successful identity gate against those
   staged, and a refused write for the evidence, the protected harness and candidates, the VM storage
   and the protected root.

Use fresh `-NoProfile` system Windows PowerShell 5.1 processes for the runner, other host scripts
and verifier. Their module search path is restricted to OS modules before any imports; a session
that already loaded untrusted functions or modules is not a trusted execution environment.

## Interrupted network campaigns

Transient observation failures preserve a possibly live campaign for the logged `-Resume` command.
Resume verifies immutable candidate/harness/bootstrap/run receipts and reloads the original credential
mode. Forced-timeout receipts remain failures after Resume. Collection attempts both guest sides
before automatic-only fixture cleanup through mounts actually acquired; successful sealing precedes
checkpoint restoration. Partial or divergent destination files are preserved and refused, not overwritten.
For exceptional isolated collection into a fresh protected evidence directory, use the
[owner recovery procedure](../../../docs/validation/2026-10-04-readiness-operator.md#resume-after-an-interrupted-or-partial-network-collection).
Do not restore checkpoints, restage disks or omit timeout receipts while evidence is pending.

Any harness change needs a newly generated, independently authenticated launcher and the owner's
elevated installation before stage/qualification, including automatic gate 36. Old runs qualify only
their exact artifacts. Tray gate evidence identifies the actual exit route; forced cleanup does not
prove graceful shutdown. Native self-tests/mock-boundary tests do not establish live Hyper-V results.

## Files

| File | Runs | Purpose |
|---|---|---|
| `New-TrustedQualificationLauncher.ps1` | build/CI, unelevated | deterministic standalone launcher from exact committed Git blobs |
| `Invoke-VerifiedQualificationLauncher.ps1` | operator-pasted trusted functions | externally pinned digest, then execution of the same memory buffer |
| `TrustedQualificationBootstrap.ps1` | generated launcher, elevated | authenticated payload validation and protected installation |
| `QualificationProvenance.psm1` | host | complete-inventory, receipt and artifact identity checks |
| `Test-QualificationProvenance.ps1`, `Test-TrustedQualification*.ps1` | tests, unelevated | tamper rejection and generation behavior; no elevated bootstrap execution |
| `WinSightQualRunner.ps1` | host, elevated, long-lived | request loop, protected copies, staging |
| `Invoke-HyperVQualification.ps1` | host, elevated, per run | stage, run, collect, seal, restore |
| `Invoke-HyperVNetworkLogon.ps1` | host, elevated, per run | gate 36 with the control VM |
| `New-WinSightControlVm.ps1` | host, elevated, once | the control VM and private switch |
| `New-WinSightHyperVVm.ps1` | host, elevated, once | the qualification VM (from an exported disk) |
| `Protect-WinSightVmStorage.ps1` | host, elevated, once | VM storage ACL, sealed disk hashes |
| `New-QualificationCandidate.ps1` | host, unelevated | assembles a candidate for a `stage` request |
| `Verify-QualificationProvenance.ps1` | host, **unelevated** | provenance and access checks of a sealed run |
| `Test-HarnessHelpers.ps1` | host, unelevated | self-checks of the helpers that need no elevation |
| `WinSightHyperV.psm1` | host | the helpers above |
| `guest\run-guest-checks.ps1` | guest, logon task | reads `mode.txt` and starts the right script |
| `guest\qualify.ps1` | guest, elevated | the gates; results into `guest-results` |
| `guest\operator-automation.ps1` | guest | the scripted operator decisions of gates 21 and 33 |
| `guest\control-network-logon.ps1` | control VM | the network-logon side of gate 36 |
