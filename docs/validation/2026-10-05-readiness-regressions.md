# Readiness regressions and verification — 2026-10-05

**Production readiness remains unestablished.** This record supersedes the storage and harness
limitations in the October 3/4 snapshots. The [draft PR #167](https://github.com/ClementG91/winsight/pull/167)
tracks the final revision, exact-head CI links and qualification status. No merge, version bump,
release replacement or repository governance change is part of this remediation.

Reviewed baseline: `3b45bbc24643aa4567b1aac0e3f1276667e2c3a5`, based on
`531b302eef3eea45389c61b94af536be9bb2adf3`. Baseline probes, main comparisons and failure analysis
preceded changes. Security changes remained with the native model; an independent native reviewer
checked the fixes. Human supervision is still required. Private local evidence retains signed
commit inventories, source selection manifests, raw TRX, failed attempts and harness decisions.
An advisory review, passing local tests or a package job does not substitute for protected CI.

## Demonstrated defects and permanent regressions

The final permanent oracles were also applied to the unchanged reviewed production baseline:
**25 assertion failures, zero test errors/skips**, covering every finding below. Tests referencing
later overloads were reduced to their verbatim selected methods and necessary helpers; production
source was unchanged. The MCP negative controls used the exact original guard predicate, with only
its input type enumeration extracted. A failed compilation attempt is retained but excluded from
defect evidence. Current passing counts are overlapping scoped suites, not a summed test total.

| Finding | Root cause and correction | Baseline assertion RED / current GREEN |
|---|---|---|
| F1 | JSON escaping expanded attacker-controlled labels beyond the audit line cap, preventing Block/Allow. Central UTF-16-safe labels have a truncation marker and full-text digest; functional rule/quarantine identities remain full. | Ten real HKCU Block/Restore/Allow/Revoke long-name cases fail on the original head; the current Response long-label suite passes. Cases include 16,383 ASCII units, HTML-sensitive text, Cyrillic, emoji and control/bidi characters. |
| F2 | A single create-new corrupt file made later damage or failed rotation permanently unwritable. Four bounded raw slots, idempotent hash/identity checks and durable pending eviction/trim make retries resumable. Small damaged tails do not force rotation. Typed results preserve audit-before-act. | Second torn recovery and rotation retry after releasing a real sharing lock fail on the original head; current recovery tests pass, including per-byte tears, identical/divergent evidence, failure boundaries and two same-session processes. |
| F3 | Oversized legacy history refused writes while reads appeared healthy. Streaming bounded migration preserves the newest raw tail and reports prefix losses/uncertainty; reads expose pending write blockers without repairing. | The original oversized-history coverage oracle fails; current coverage/migration and post-publication inherited ACL-denial retry regressions pass. |
| F4 | One null/keyless rule invalidated every neighbor. Invalid individual rules are ignored visibly and dropped only by a successful write. Malformed/unknown envelopes remain preserved and unwritable; confirmed absence is distinguished on the same acquisition. | Both null/keyless-neighbor tests fail on the original head; 37 focused rule regressions pass, including unknown version/corrupt bytes, limits, rollback and write failures. |
| F5 | Compaction kept one row per action ID and erased Prepared intent. Writers now keep the newest row per action/phase and retain complete available groups within physical byte/line budgets. | The original undo test loses two of four physical phases; the current phase suite passes. A real capacity refusal leaves the source unchanged and does not invent an absent undo record. |
| F6 | Configuration captured before restore, unconditional teardown, repeated cleanup and invisible prompting drivers broke recovery/evidence. Capture follows restore; immutable receipts bind Resume; uncertain live state is preserved; both collections precede automatic-only fixture cleanup and sealing precedes restore. Hidden NonInteractive drivers have actual PID/phase heartbeats. Tray evidence records the path and observed exit. | The original post-checkpoint memory oracle fails. The initial focused lifecycle RED had 20 genuine failures and four negative controls passing; all 24 lifecycle cases now pass, plus all four actual unelevated Windows PowerShell 5.1 self-tests. |
| F7 | The CLI write-detector positive control had been weakened; new verbs/SDK aliases escaped the named MCP guard. Restore true CLI-rooted IL detection and add real UI roots and same-predicate negative canaries. PS5 instrumentation preserves the 30/120-second oracles, drains concurrently with bounded output and preserves the first exception through cleanup. | Seven original MCP canaries fail; current MCP suite passes 136 cases. The actual old fixture hangs on an exited parent with a live inherited pipe; the current 30-second cancellation oracle passes. Flood, blocked-child/secondary-cleanup, native-exit and same-mode no-op controls pass. |

Final scoped F7 checks pass: **108 Response, 179 Core, 174 targeted Application, 136 MCP,
260 Dashboard and 10 phase tests**, all without skips, plus **whole-solution** format verification.
Earlier F1–F6 formatting checks were scoped and must not be presented as global verification.
One whole-solution import-order failure was corrected by reordering two using directives; no
assertion was weakened. Independent review also removed a race in the pipe test's PID publication
by atomically renaming a fully written adjacent file, with unchanged deadlines and assertions.

## Recovery and audit contract

See [RECOVERY.md](../RECOVERY.md) for every typed journal/rule status, retry procedure and deliberate
backup recovery. Restorative actions still require a durable intent: unavailable storage is an
explicit refusal, never permission to Resume/Restore/Revoke without audit. After a machine change,
a failed completion or best-effort undo link must not trigger automatic replay.

Normalized active history is 16 MiB / 10,000 physical lines; rotation retains complete available
groups within 8 MiB / 5,000 physical lines. Four raw evidence slots plus an 8 KiB index bound live
files to 80 MiB + 8 KiB; all fixed staging names give a conservative 160 MiB + 16 KiB. Oversized
external legacy files can exceed this before maintenance. This is bounded local history, not an
immutable forensic archive or seven-day retention guarantee. Same-user state remains editable.
Genuinely missing accounting metadata initializes a new state; it cannot prove no earlier losses.
Unknown newer enum values remain opaque evidence; unsupported rule envelopes are not overwritten.

Current journal/rule writers use a Global mutex. Older Local-mutex versions must be stopped before
upgrade or recovery. Same-session process tests do not qualify different sessions, accounts or
integrity levels. Partial individual network evidence copies are refused rather than overwritten;
the [operator annex](2026-10-04-readiness-operator.md#resume-after-an-interrupted-or-partial-network-collection)
documents owner-supervised recovery into a fresh protected evidence directory with unchanged receipts.

## Latency and PowerShell timing limits

Same local probe and inputs, one sample each; timestamps/GUIDs cause small serialized-size variation.
These measurements are not a percentile, throughput guarantee or proof of optimization:

| Scenario | Original append / undo (ms) | Corrected append / undo (ms) | Corrected outcome |
|---|---:|---:|---|
| 10,000 physical rows, approximately 1.94 MB | 134.1 / 59.3 | 130.1 / 49.1 | Rotated / Updated |
| Approximately 16 MiB | 187.8 / 306.2 | 171.7 / 352.0 | Appended / Updated |
| Approximately 18.82 MB legacy state | 139.1 / 131.8 | 538.2 / 145.5 | Rotated / Updated; original refused both |

Undo at the byte cap was slower in this sample. Legacy migration restores availability at a measured
cost. Local component DLLs and probe-source hashes are retained privately; these are not CI packages.
New publication/counter boundary tests establish modeled retry behavior, not physical power-loss proof.

Historical native ARM64 TRX for `b0ffcd1` had 23 PS5 fixture cases at 22.7–24.9 seconds each (about 538 seconds
total). The cause remains **unproven**. Host-monotonic instrumentation records actual received closed
phase signals, parent exit and EOF-only drain; it does not measure child CPU time. A same-mode no-op
control and real inherited-pipe control distinguish observable phases without raising deadlines.
Output retention is bounded to 32,768 characters per stream while overflow is still consumed.
Digests cover retained decoded text prefixes, not full raw streams. Synchronous Process.Start stays
outside the existing watchdog origin; best-effort tree kill cannot prove every descendant exited.
Final native ARM64 CI must establish its own results and timing evidence on the pushed head.

## Support and qualification status

Primary qualification scope is Windows 11 x64 within the supported .NET 10 lifecycle. The
[official .NET 10 OS matrix](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md)
does not list Windows 10 22H2, while the unchanged installer accepts `10.0.19045`. Installer acceptance
and the `windows10.0.19041.0` API target do not establish OS support or qualification. Windows Server
CI is additional build/test evidence. Native ARM64 privileged runtime and x64-on-ARM64 remain unqualified.

Historical `readiness-600acf4-full-02` is sealed: **31 PASS, 0 FAIL/NOT_RUN**, with **12/12 protected
provenance checks reverified unelevated on October 5**. It qualifies only candidate `600acf4` and the
installed `0793f78` harness. Neither this result nor published v0.14.2 evidence transfers to new bytes.

| Required final evidence | Status at this local regression record |
|---|---|
| Full local Definition of Done on committed final revision | Pending final execution; exact results belong to the PR evidence |
| Both x64 CI legs, native ARM64, packages, aggregate and CodeQL | Pending final pushed revision; do not reuse earlier runs |
| New response gates and full VM campaign | NOT_RUN for final bytes; changed harness requires authenticated owner installation |
| Automatic Network Logon gate 36 | NOT_RUN for final bytes; owner installation precedes automatic disposable credentials |
| Real disk-full, failed UI delivery, adverse bootstrap and physical crash trials | NOT_RUN; native fault-boundary tests are narrower evidence |
| Cross-session/account/integrity and both 168-hour workload profiles | NOT_RUN; keep frozen budgets in the October 3/4 protocol |

Regenerate the trusted launcher from the final signed committed blobs, independently authenticate its
SHA-256 and stop for the owner's elevated installation. UAC and passwords belong to the owner.
Never elevate a mutable checkout. Only afterward stage the exact final CI artifact, run the response
gates, full campaign and automatic gate 36, and verify every seal unelevated. Human acceptance,
remaining platform/load decisions and any future release remain owner-supervised.
