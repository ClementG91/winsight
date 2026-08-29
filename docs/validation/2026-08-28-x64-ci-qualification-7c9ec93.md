# x64 CI VM qualification - 2026-08-28 - STOP / RED

## Evidence identity

| Field | Value |
|---|---|
| Runtime candidate | `7c9ec935ed21d04483c553031c8d7dd70188d320` |
| Version | Declared `0.11.6`; installed product version `NOT_RUN` |
| Artifact kind | **`ci`** — pre-publication artifact; this record makes no claim about release binaries |
| CI run | `ci.yml` run `33179811048`, `head_sha=7c9ec935ed21d04483c553031c8d7dd70188d320`, `conclusion=success` |
| CodeQL | Run `33179810527`: Actions and C# analyses `success` on the same candidate |
| Target | `WinSight-Qualification-7c9ec93`, Windows 11 `10.0.26200.8875`, native x64 VirtualBox VM |
| Control | Separate disposable VM `WinSight-Control-7c9ec93`; provisioned but not started because qualification stopped during target bootstrap |
| PowerShell | `NOT_RUN`; no authenticated/elevated native Windows PowerShell session was available |
| Target snapshot | `S0-clean-before-winsight`, UUID `de916fad-d636-4271-9a7e-7c44908c4220`, restored and powered off after the attempt |
| Control snapshot | `control-clean-7c9ec93`, UUID `d66710d7-6d00-4db3-9c2d-7ef762d8bc93`, never started |
| Evidence root | `D:\WinSight-Host-Evidence\7c9ec93-ci-33179811048`, outside the VM snapshot |
| Evidence manifest | SHA-256 `59866328820438800A8F26D243711186F6D62082AE6729DBC254F0A15E1564E0` |
| Classification | **STOP / RED before candidate execution** |

The target and control were full disposable clones, not linked clones. Clipboard and drag-and-drop
were disabled. Each VM had NAT plus a distinct host-only adapter for the planned remote Network Logon
gate. The fresh target evidence VDI was stored under the host evidence root with VirtualBox medium
type `writethrough`; it was therefore outside snapshot rollback. The target was restored to `S0` and
verified powered off before this record was written.

## Artifact binding

The `winsight-win-x64` Actions artifact was downloaded on the host from run `33179811048`. The two
expected hashes were calculated on the host, then the same files were copied to the host transfer
area exposed to the guest. No candidate file was executed or extracted in the guest.

| Artifact | Provenance | SHA-256 |
|---|---|---|
| GitHub Actions artifact archive | Actions artifact `9689378098`, run `33179811048` | `9A5AB8EC9E516E10F8E18DB930E9D8CF790626993F95081C561D9E9107FD4F06` |
| `winsight-v0.11.6-win-x64.zip` | Inner portable ZIP, hashed on the host after `gh run download` | `AA544D86EA61D0F039B8AAFE0933AE3180057A28BDDAA7368F8D7BFEF82034FB` |
| `winsight-v0.11.6-win-x64-setup.exe` | Setup, hashed on the host after `gh run download` | `70579F3DA17C2ECFE04FCD51A5E10565241E8A1627080996A3541CD4EBE0F7F4` |
| Target S0 host record | Host-side `take` proof | `6FFAD5EEE3801143347C7432A7EBE30A48DA8BE5897329E7892FC8B10ECA7ED3` |
| Control snapshot host record | Host-side `take` proof | `910B8A037C1BFAE9464685AB7935EE637506E335BC3FC48EB597DD2DE1F834C3` |
| Target S0 restore record | Host-side `restore` proof | `93E9943C725F7033CE18CE01EE1BFAED1AC891FC39ACF3D19DAF5B3584C7C28E` |
| Bootstrap blocker record | Host-side access evidence | `DBDF8DBD4C538EFEDF99651A9AA466BC55076B49E07A730ABA73A7D4BA128E8B` |

## Stop condition

The clean target booted successfully and VirtualBox Guest Additions `7.2.4` reported one logged-in
local user, `vboxuser`. Guest Control rejected the credential from the local VirtualBox unattended
configuration both without a domain and with the local computer domain explicitly supplied. No
pre-provisioned remote administration channel was available: TCP 22, 3389, 445, 5985 and 5986 all
returned closed from the host-only network.

The protocol requires a native Windows PowerShell `-NoProfile` session and later an elevated session.
Resetting the account offline, injecting commands into a terminal through the VM console, or
installing an unauthenticated bootstrap would have bypassed that boundary and changed the clean
candidate environment. The run therefore stopped fail-closed before section 3 and before any
candidate binary was executed.

Literal bootstrap result:

| Check | Result |
|---|---|
| Guest Additions ready | `true`, version `7.2.4` |
| Logged-in user | `vboxuser` |
| Guest Control with unattended credential | `FAILED`, nonzero host command exit |
| Guest Control with explicit local domain | `FAILED`, nonzero host command exit |
| Remote management ports | `22=false`, `3389=false`, `445=false`, `5985=false`, `5986=false` |
| Candidate executable launched | `false` |
| Service installed | `false` |
| WFP modified | `false` |
| ETW session modified | `false` |

## VM gate results

| Gate | Literal result |
|---|---|
| Candidate/run identity | `PASS`: exact SHA, run `33179811048`, conclusion `success` |
| Host artifact hashes | `PASS`: ZIP and setup cardinality `1/1`, both hashes recorded above |
| S0 and external evidence storage | `PASS`: snapshot take and restore recorded; evidence medium `writethrough` |
| Protected-root bootstrap | **`STOP / RED`**: no authenticated guest execution channel; no candidate execution |
| Authenticode and installer | `NOT_RUN`, no exit code |
| WFP contract | `NOT_RUN`, expected `26/26`, no exit code |
| WFP negative control | `NOT_RUN`, expected `26 checks / 1 failure / exit 1`, no exit code |
| Pre-arm cleanup | `NOT_RUN`, expected `17/17`, no exit code |
| Full WFP/SCM | `NOT_RUN`, expected `35/35`, no exit code |
| Trust boundary | `NOT_RUN`, expected `13/13` with no skip, no exit code |
| Local elevated/restricted IPC | `NOT_RUN`, expected `7/7`, no exit code |
| Remote Network Logon | `NOT_RUN`, expected `7/7`, no exit code |
| Independent service observer | `NOT_RUN`, expected `3/3`, no exit code |
| ETW lifecycle and recovery | `NOT_RUN`, expected `19/19`, no exit code |

## Additional privileged audit checks

### WFP sublayer weight

`NOT_RUN`. No enforcement transition occurred, no WFP state XML was generated, and the observed
weight/order of sublayer `d7a9b1e1-5c3a-4b8e-9f21-6c0a7e2d1f34` is therefore unknown.

### App-ID derivation fallback

`NOT_RUN`. No test application was blocked, renamed or restored. There are no target/control curl
results and no claim about BFE-derived application identity or the UNC non-applicable path.

### Nonzero exit on endpoint loss

`NOT_RUN`. The service was never installed or started. QueryServiceConfig2W, named-pipe squatting,
SCM failure/recovery events, and the 5-second/30-second recovery sequence were not exercised.

## What was not exercised

No installer, portable executable, protected candidate root, signature state, PE architecture,
product version, MCP smoke, EN/FR/ES UI, WFP, SCM, IPC, Network Logon, ETW, App-ID fallback or
endpoint-loss behavior was exercised. Native Arm64 and x64-on-Arm64 were not exercised. This record
does not qualify the existing `v0.11.6` release or any future release artifact. The GitGuardian
incident associated with PR #145 was not changed because the qualification stopped at the first
fail-closed condition.

## Classification

This campaign is **RED / NOT QUALIFIED**. The red result is an environment bootstrap failure, not a
demonstrated product defect, but it prevents every runtime and privileged claim. A new campaign must
start from a clean snapshot with a deliberately provisioned, authenticated administration channel;
it must not resume this run or reinterpret any `NOT_RUN` gate as PASS.
