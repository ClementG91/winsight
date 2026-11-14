# PR #167 x64 qualification - 2026-11-14

**Recorded result: all 32 distinct harness gates passed across the full and separate network
campaigns on the unchanged x64 CI artifact of PR #167 head `f2d4ef7`.** Both evidence sets passed
12/12 provenance and protection checks from the protected verifier, unelevated. This is bounded
functional evidence for those exact bytes, not blanket production certification.

## Candidate identity

- Source and harness commit: `f2d4ef734059b9d52e35837cdf9f2433997423f2`, which contains `main` at `515abc9`.
- Build: [CI run 43609904605](https://github.com/ClementG91/winsight/actions/runs/43609904605), all
  jobs green (Windows 2022 x64, Windows 2025 x64, native Windows 11 ARM64, both packages, CodeQL).
- Artifact: `winsight-win-x64`, artifact `14120046237`, ZIP digest
  `sha256:39af267f96d4ed74bf3983086adea4316e98d59e5d6e7204ee94129d2287c0dc`, staged unchanged.
- Version string: 0.14.2 (unpublished qualification candidate; no release asset was replaced).
- Guest: Windows 11 Pro 10.0.26200, native x64, Hyper-V generation 2.
- Target: `WinSight-Qualification-HV`, 4 GiB RAM for the full run and 3 GiB for the network run;
  checkpoint `S0-hyperv-autorun`.
- Network control: `WinSight-Control-HV`, 2 GiB RAM; checkpoint `C0-control`.

| Artifact | SHA-256 |
|---|---|
| `winsight-v0.14.2-win-x64.zip` | `bcf169d0471828ba07795871da19d80d63f320f6bfeca6782933ee30e66d2ebc` |
| `winsight-v0.14.2-win-x64-setup.exe` | `4b76e8fae58922b4709d09d117feca2256c573d507061f43f95df96aa70f68c7` |
| `winsight-v0.14.2-win-x64.spdx.json` | `361be1270ae41fa9953df04a071a062cb3172595706460a30378fe8c6b994716` |
| Qualification launcher `winsight-0.14.2-f2d4ef7-qualification-local.ps1` | `1525edab8a2504ad1e97b50691ff5a098b643c0f71eb3502d982319edea4d39a` |
| Previous published `winsight-v0.14.2-win-x64-setup.exe` (upgrade baseline, `0793f78`) | `492f3f91ce58b815ec81508f1560aa05aa408045f82c497b2a003c810cd3bc05` |

## Trusted entry and evidence handling

The owner pinned the launcher digest above, hashed one bounded byte buffer and executed that same
buffer in an elevated Windows PowerShell 5.1 process. It installed the harness into the
administrators-only `C:\Program Files\WinSight-Qualification-Harness-f2d4ef7`. The VM storage was
then resealed with `Protect-WinSightVmStorage.ps1` from that installation, and the runner started
only from it. The runner staged the CI artifact, ran both campaigns on disposable guests and sealed
each evidence set before restoring checkpoints.

After both runs, `Verify-QualificationProvenance.ps1` from the protected installation ran
**unelevated** with the external commit and launcher digest: **12/12 checks passed for each run**.
They cover the evidence inventory, the complete harness and candidate scripts bound to `f2d4ef7`,
the bootstrap receipt, the identity gate's artifact triplet, and refusal of ordinary-user writes to
the run, seal, results, harness, candidates, VM storage and protected root.

The seal is a SHA-256 inventory protected by host ACLs, not a digital signature or protection
against a malicious administrator.

## Runs

| Run | Guest UTC | Selected gates | Result |
|---|---|---|---|
| `pr167-f2d4ef7-full-01` | 2026-11-14 17:02:13 - 18:11:15 | All except 36 | 31/31 PASS |
| `pr167-f2d4ef7-network-01` | 2026-11-14 19:44:06 - 19:46:35 | 01, 36, 99 | 3/3 PASS; control PASS |

The full campaign covers identity, architecture and unsigned policy, CLI/MCP contracts, installer
lifecycle, all-users service and upgrade from published v0.14.2, scanners and MSIX, process response,
holders and signature UI, Guardian block/restore/allow/revoke and cleanup, dashboard languages,
Cloud Files, interpreter triage, ETW lifecycle/attribution/DNS/outbound/pre-opened writes, WFP
contract, negative control, pre-arm and full transitions, trust boundaries, local IPC and residue.

The network gate used automatic disposable credentials; no operator password dialog was needed.
It passed **7/7** checks from the control VM: Network logon token (`S-1-5-2=true`,
`S-1-5-4=false`), unavailable exit code, unreachable authenticated pipe, `ServiceUnavailable` and
`mutation=none`. The target observer passed **5/5**, with pre- and post-canaries PASS and the same
service process before and after.

Both guests logged on unattended within two minutes and published their logon through the Hyper-V
`Guest` KVP pool. This confirms the `f2d4ef7` fix: the previous harness `09c4f66` wrote to the
`Auto` pool, which the host never reads, and stopped a healthy run with a false
`guest-logon-missing` alert.

### Evidence inventory anchors

Raw logs are retained locally, not uploaded: they can contain machine identifiers and scan findings.

| Run | SHA-256 of `SHA256SUMS.txt` |
|---|---|
| `pr167-f2d4ef7-full-01` (32 files) | `d79a0edf1b37764d9fa8137c633a3f8ed547eeb7a3a97b7d6cda9e0bdd1a26c5` |
| `pr167-f2d4ef7-network-01` (18 files) | `d0344ca1d3e61c59751fa01b405552430131402ba89e534bb2ea90039c773184` |

## Still open

- Native Arm64 privileged runtime and x64-on-Arm64: no Arm64 VM is available. Native Arm64 build,
  tests, package and installer pass in CI only.
- Real disk-full, failed UI delivery, adverse bootstrap and physical crash trials (RB-02); native
  fault-boundary tests are narrower evidence.
- Live pre-launch substitution and receipt tampering acceptance in a disposable VM (RB-01/RB-04).
- Cross-session/account isolation and the two 168-hour workload profiles (ETW throughput and soak).
- Authenticode: distribution remains unsigned; gate 02 accepted the documented unsigned policy.
- Dependency updates held back for review: ModelContextProtocol 2.4.0 (#177), Microsoft.NET.Test.Sdk
  18.12.0 (#176) and Microsoft.Diagnostics.Tracing.TraceEvent 4.0.0 (#173). Shipping any of them
  changes the bytes and needs its own qualification.

Commits after `f2d4ef7` that change only documentation do not change the qualified bytes. Any code,
package or harness change must be qualified on its own exact bytes.
