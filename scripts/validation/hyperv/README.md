# Hyper-V qualification harness

The host side of WinSight's disposable-VM qualification (`docs/validation/VM_QUALIFICATION_KIT.md`),
kept in the repository so that what runs elevated on the host, and what runs in the guest, is
reviewed like any other code and can be bound to a commit.

It installs nothing on the host beyond two Hyper-V VMs and a private switch, never authenticates to a
guest, and never touches the development workstation's own WinSight, WFP or services: every
privileged step happens inside a VM that is restored to a clean checkpoint afterwards.

## Trust boundary (RA-01)

The first version kept its scripts, the staged candidate, the VM disks and the evidence at the root of
a data volume, where Authenticated Users have Modify by inheritance, and its elevated runner wrote,
moved and deleted files there. Hashes of that evidence proved it was consistent, not that nobody had
changed a script before a run or a result after it. Now:

| Location | Who can write | What the runner does there |
|---|---|---|
| `<vol>\WinSight-Qualification-Requests` | the requesting user | reads request files (≤ 4 KB), never writes, moves or deletes; reads `candidates\<name>` when asked to stage it |
| `<vol>\WinSight-Qualification\harness\<stamp>` | administrators | the harness copied from this folder at start, re-hashed before every action |
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

What this does not close: someone running as the operator at the moment the operator starts the
runner could still alter it first. The runner records its own git blob id and the harness it copied,
so `Verify-QualificationProvenance.ps1` detects that afterwards against the reviewed commit. A local
rehearsal is still not a CI-attested release.

## Once

1. Build the VMs (`New-WinSightHyperVVm.ps1`, then the runner's `control` request for the second VM).
2. Protect their storage, elevated: `.\Protect-WinSightVmStorage.ps1`. It seals the disk hashes in
   `<vol>\WinSight-Qualification\sealed\vm-storage-<stamp>.txt`. A VM whose disks sat in a folder any
   user could modify is only as trustworthy as that folder was; rebuilding it into protected storage is
   what removes the doubt about the past.

## Each campaign

1. Commit the harness and note the commit (`git rev-parse HEAD`). Check it out as a worktree on the
   volume that will hold the qualification data (`git worktree add <vol>\WinSight-Build\wt-<sha> <sha>`)
   and start the runner from that clean tree, elevated (the operator accepts the UAC prompt):
   `Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','<vol>\WinSight-Build\wt-<sha>\scripts\validation\hyperv\WinSightQualRunner.ps1'`
2. Build the candidate unelevated from a clean checkout of the commit (a worktree on a drive with
   room: `Build-Release.ps1 -Version <v> -Architectures x64 -DisableSignature`), then assemble it with
   `New-QualificationCandidate.ps1 -BuildTree <checkout> -Name <name> -PreviousInstaller <published setup>
   -PreviousSha256 <its published hash> -PreviousCommit <its commit>`: the artifacts, the repository's
   `scripts` at that commit, the published installer the upgrade gate starts from, and
   `candidate.json` binding them by SHA-256, in `<vol>\WinSight-Qualification-Requests\candidates\<name>`.
3. Queue requests as JSON files with unique names in `<vol>\WinSight-Qualification-Requests`:
   `{"action":"stage","candidate":"<name>"}`, then `{"action":"qualify","runName":"...","gates":[...],"memoryGB":4}`,
   `{"action":"network","runName":"...","memoryGB":3}` for gate 36 (the operator types the disposable
   password in each VM; the control VM runs with 2 GB, and the run is refused up front if the host
   cannot hold both VMs plus 0.5 GB), `{"action":"stop"}` at the end. Progress: `<vol>\WinSight-Qualification\runner\status.json` and
   `runner.log` beside it; reading or following them while the runner works is safe (WS-83).
4. Verify each run as an ordinary user before citing it:
   `.\Verify-QualificationProvenance.ps1 -RunDir <vol>\WinSight-Qualification\sealed\<run> -HarnessCommit <sha>`
   Every check must print PASS: the seal, the harness blob ids against the reviewed commit, the
   candidate scripts against the candidate's commit, the artifacts the guest checked against those
   staged, and a refused write for the evidence, the protected harness and candidates, the VM storage
   and the protected root.

## Files

| File | Runs | Purpose |
|---|---|---|
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
