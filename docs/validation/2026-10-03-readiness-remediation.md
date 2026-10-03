# Readiness verification and remediation — 2026-10-03

**Full production readiness remains unestablished.** A1/A2 are confirmed and corrected locally;
A3 adds a reproduced HTTP buffering defect. Published v0.14.2's functional qualification remains
valid for its exact bytes. The corrected candidate needs its own CI, human review and VM evidence.

Baseline: `531b302eef3eea45389c61b94af536be9bb2adf3`; isolated branch
`codex/readiness-verified`. The original checkout and its untracked audit were preserved.
This is a targeted source/evidence review, not a complete pentest or a claim that no defects remain.

## Verification of the supplied audit

| Claim | Verified result / limit |
|---|---|
| Architecture | XML project references recomputed: 24 production, 23 test projects, no cycles. SYSTEM service references Firewall and NetMonitor, no UI/Application. Nullable, analyzers, warnings-as-errors, deterministic output and central package versions confirmed. |
| IPC authority and bounds | SYSTEM-owned ACL, Network SID deny, first-instance reservation and capability dispatcher confirmed in Firewall. Limits: 64 KiB frame, 128 policies, 32 KiB path payload. Authentication and mutation admission remain separate. |
| Automatic access / MCP | Handle-based local acquisition refuses reparses and unavailable cloud data. MCP registers stdio and posture-only gateway; existing IL reachability tests cover forbidden mutations. These controls do not establish an exhaustive elevation review. |
| CI / release | Workflow SHA pinning, narrow permissions, no persisted checkout credentials, coverage floors and release inventory/attestation checks confirmed. Historical CI `36466345720` and CodeQL `36466345163` succeeded on `531b302`; release `36345608152` succeeded on `0793f78`. |
| Published v0.14.2 | GitHub ZIP/setup/SBOM/launcher digests match the [September record](2026-09-28-v0.14.2-x64-qualification.md); annotated tag signature API reports valid. That record contains 32 distinct gates and four 12/12 proof sets. Protected raw VM logs were not reauthenticated here. |
| A1 and A2 | Reproduced with real NTFS sharing locks and synthetic local journals; genuine failing assertions recorded before fixes. See below. |
| Resource caps | DNS queue 1,024; ransomware changes 8,192; signature cache 4,096; pending WFP identities 128; attribution 4,096 confirmed. Capacity is not throughput or endurance evidence. |
| Governance | On the October 3 API reads, main requires three checks, current head and signed commits; admins included, force push/deletion forbidden. Required approvals = 0. CODEOWNERS **exists**, but code-owner approval is not enforced. v0.14.2 reports `immutable=false`; accessible repository rulesets list is empty. Organization policies are not fully inventoried. |
| Reproducibility / CodeQL | No committed package lockfiles/locked restore. Default CodeQL setup is external to the clone: C#/Actions, default suite, weekly, remote threat model. No open alert returned; neither deterministic builds nor an empty alert list prove absence of vulnerabilities. |
| Old numbers / roadmap | The supplied audit reports 3,639 passing tests and 50,988 production C# lines on its baseline. These are historical, not current counts. The 431 MB install estimate was not remeasured. Packaging and additional detectors remain optional roadmap items. |

Public metadata references: [CI](https://github.com/ClementG91/winsight/actions/runs/36466345720),
[CodeQL](https://github.com/ClementG91/winsight/actions/runs/36466345163),
[release run](https://github.com/ClementG91/winsight/actions/runs/36345608152).

## Product corrections and evidence

| Item | Result and regression evidence |
|---|---|
| A1 — revoke/Allow rollback | Empty rule sets are persisted by flushed atomic replacement; failure cannot return successful revocation. Typed outcomes distinguish storage failure and absent target. Corrupt/unsupported stores are not overwritten by Add. Tests cover locked last/intermediate rules, denied creation, corrupt state and successful/failed Allow rollback with journal failure. |
| A2 — reads / diagnostics | Reverse JSONL reader: 8 KiB blocks, 16 KiB lines, 16 MiB inspected bytes, 10,000 physical lines including corruption/blank lines. Latest physical action wins. Read coverage exposes unavailable, malformed, limited and preserved-evidence states; Application reports incomplete coverage. |
| A2 — writes / recovery | Append preflights the bounded store. Rotation atomically includes the new entry and reports durable/failure status. Corruption is preserved byte-for-byte in one create-new `.corrupt.jsonl` before compaction; no overwrite. Oversized legacy stores and a second recovery collision fail closed, requiring operator recovery. Tests cover limits, torn writes, rotation sharing failure, concurrent instances and a separate process holding the mutex. |
| A3 — VirusTotal | Default completion buffered a 3 MiB body before the old limit. Headers-first streaming now rejects declared oversize without reading; absent/false length is capped at 1 MiB plus one probe byte. A linked deadline covers body reads; caller cancellation propagates. Strict UTF-8, valid exact-limit JSON, status errors and stalled-body cancellation tested with synthetic keys and fake handlers. No live network call. |

Retention is bounded local history, **not seven-day guaranteed retention or a forensic archive**.
Healthy rotation keeps at most 5,000 newest actions / 8 MiB, permitting further bounded growth.
Evidence plus active journal consume at most approximately 32 MiB under automatic writes; an
already oversized external file is retained and refused. A hostile same-user process can still
alter this user state. `Local` mutex scope does not establish cross-session serialization.

Harness trail (local evidence; no merge authorization):

- A1: `6be7d296-1966-4f0c-86bd-abed8e7a33b2`, genuine red then green; human review required.
- A2 reader: `9dd93d96-0431-47d9-b0fb-2367121a0c10`; helper extraction:
  `57196e27-9a6f-4592-8c6f-8d0cf922044e`; supplemental tests:
  `fcfa2cde-7fb1-4d84-86ad-47fb3d0fb6da`, local checks/reviews completed.
- A2 integration: `597be2dd-5b50-450b-a28a-5de1aa943093`, red and final checks pass,
  **finish blocked: missing current Jev review**, because complete review context exceeds its
  20 KB bound. Earlier attempt `69dc5ce3-9535-45d5-8e19-c6d26ed93930` is also retained as blocked.
  No limit increase or fabricated approval: independent human review remains required.
- A3: `5164a54b-a806-409b-968a-db1fc8d67f4d`, red then 178 Core and 11 parser tests,
  Release build and format pass; human review required.
- Final reconciliation/full checks: `4569316f-1170-49a5-9354-1bc68d489d81`.
  Actual results and fingerprints are retained locally in the router evidence directories and
  `out/readiness-final/validation.json`. This record alone does not assert those gates passed.

## Support and qualification contract

Primary scope: **Windows 11 x64 within the supported .NET 10 lifecycle**. Existing published-byte
VM evidence is Windows 11 build 26200. Each additional supported client release needs a named
baseline and critical-path smoke; Server CI is not client runtime qualification. Windows 10
compatibility is unqualified; `windows10.0.19041.0` is an API contract. Microsoft's
[.NET 10 supported OS list](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md)
does not list Windows 10 22H2. Arm64 runtime remains outside this remediation's qualification scope.

Two proposed **endpoint** profiles use the same engine. They are test targets, not measured capacity:

| Profile | Reference workload to freeze before execution |
|---|---|
| Personal | 4 vCPU / 8 GiB VM; 7 days mixed monitoring, one full scan daily, 10 filesystem changes/s and 10 DNS events/s; hourly 60-second bursts of 500/s. |
| Business workstation | Same reference hardware; 7 days monitoring, daily scan, 100 filesystem changes/s and 100 DNS events/s; hourly 60-second bursts of 2,000/s; two concurrent standard-user sessions as a separate mandatory leg. |

Proposed acceptance for each profile: 1-second resource samples and event-ID counters; steady
monitoring CPU p95 <= 10% of total VM capacity (scan windows separately measured); combined dashboard
and service private bytes <= 512 MiB; settled memory, handle and thread counts <= 120% of the day-one
baseline after workload recovery; ordinary alert latency p95 <= 2 s / p99 <= 5 s. Report both ordinary
and overload latency. Every injected event is either delivered or contributes to an explicit loss/
coverage counter; no silent loss. Journals respect documented byte/line caps. Stop/restart leaves no
orphan ETW sessions and returns to AuditOnly/effective-state correctness. Freeze provider availability,
candidate hashes, VM image, counters and sampling scripts in the reviewed campaign manifest. Missing
measurement or failure leaves the profile unqualified; change thresholds only by recorded review.
Seven-day monitoring is independent of bounded action-history retention. Fleet collection, central
retention, remote control and enterprise SLA are not implemented by these profiles.

## Remaining gates and decisions

| Priority | Required execution / acceptance |
|---|---|
| P1 | New exact-byte x64 candidate: protected CI, signed revision, reviewed release inventory and trusted launcher; install/upgrade/uninstall and critical response paths. September results are not reused for different bytes. |
| P1 | Guardian disk-full/UI failure: disposable VM/VHD only; saturate its data volume, inject >4,096 arrivals/coverage gains, verify degraded state and no false acknowledgment, free space, restart and prove effective delivery. Never fill the host disk. |
| P1 | Execute both frozen load/7-day campaigns above; report measured p95/p99, dropped events and recovery rather than an invented scalability verdict. |
| P2 | Trusted harness: substitute pre-launch script/candidate, alter receipt, duplicate/omit inventory and use wrong artifact; reject before elevation/qualification, with protected negative-control receipts. |
| P2 | Sessions: distinct standard accounts, same account across sessions, admin non-elevated/elevated and fast switching; isolate per-user state, verify capabilities, mutex naming/contention and no falsely successful writes. |
| P2 | Known Folder Move/Cloud Files decoys: disposable sync root; plant/watch/clean, substitute/modify files, preserve foreign data, no foreign hydration, record provider errors and recovery. Gate 17 proves reads, not this entire lifecycle. |

The current `Get-VM` probe was denied for missing Hyper-V management permission. These VM gates
remain unexecuted in this remediation and need an authorized operator via the trusted harness.

Owner-supervised governance choices remain open: require an independent reviewer when available,
otherwise record operator acceptance; protect future release tags and enable immutable releases;
choose lockfiles/locked restore and NuGet sources, then prove two clean-build comparisons; export
CodeQL configuration or review a versioned migration without losing required checks. No repository
settings were changed. Corrected releases require a new version; never replace v0.14.2 assets.
Authenticode remains an accepted, disclosed distribution limit, with no publisher identity claimed.
