# Readiness operator evidence and next campaign — 2026-10-04

**Production readiness remains unestablished.** This annex supplements the
[October 3 source review](2026-10-03-readiness-remediation.md). The operator supplied the
protected execution path; the earlier unelevated Hyper-V access denial is no longer an execution
blocker. The initial VM execution phase changed no product, privileged harness, repository policy
or release. The later product/test follow-ups are identified separately below.

## Candidate and trust chain

The candidate is the exact x64 PR CI artifact from signed commit
`8c1dd46a1a3c8e3ffe800deed009b8bc182574ec`,
[CI run 37156828262](https://github.com/ClementG91/winsight/actions/runs/37156828262).
Artifact ID `11286118250`, container digest
`sha256:9ead42c110e3de2fa43b3dfba957541cf3a8de9e6f0d0ceb90fc372a029c0fbd`.
The filenames retain version 0.14.2; these corrected bytes are **not a published release**.

The packaging checkout is GitHub's PR merge commit
`f218c6cfe6325104e7c1bbfb2fa727251efa7fc8`, parents `531b302` and `8c1dd46`.
Its tree is `b421324de867bbd5e8d441423ffbdf07a6981fc8`, independently matched to the signed
head's tree. The candidate manifest's commit identifies the exported source; it is not a claim
that CI checked out that head directly or that a local rebuild produces identical binaries.

| Artifact | SHA-256 |
|---|---|
| x64 setup | `dc5c31726d8e1779195b6e274a2d72e0b271a3b98cc49c03a04e704ce7673e96` |
| x64 ZIP | `39c55fddd52904dbca0a7ee9cd1c01f235388db9d812df95aa3a69c5212e5f40` |
| SPDX SBOM | `485ab8cc1f495ee5a67ae41042a4f8963b11fe3b4b93d0b1b66592486516538c` |

The existing protected harness is source commit
`0793f783007a79e9057c7296e549a2fe6a307cc2`, authenticated by the independently pinned
launcher digest `173c30536eb4db0ce92cd15fd6af4d32672deb2f9e75222ef0c40d23311617bf`.
Its complete installed inventory matches its receipt and committed sources. Candidate scripts were
exported byte-for-byte from Git; the qualification scripts are unchanged between these commits.
The protected runner staged into a fresh campaign root and used its disposable VM/checkpoint.
Private raw logs, local paths and machine identifiers remain in protected local evidence.

## Executed evidence

`readiness-8c1dd46-response-01`: **6 PASS, 0 FAIL, 0 NOT_RUN**, on Windows 11 x64 build 26200.
Selected gates: identity/protected root, CurrentUser installer lifecycle and languages,
Guardian Block/Restore, Allow/silent re-arrival/Revoke, Guardian cleanup and final residue.
The protected verifier subsequently ran unelevated: **12/12 PASS** for sealed hashes, complete
harness/candidate identity, authenticated bootstrap and refused writes to protected locations.
The host log records sealing followed by restoration to the clean checkpoint.

Gate 13 used forced process termination because tray Exit could not be driven. It proves probe
cleanup, not graceful UI shutdown. Gate 99 independently found no process/service/ETW/probe residue.
Nominal revocation is proven here; locked/damaged-store failures remain covered by the separate
local regression tests, not this VM gate.

The separate 31-gate non-network campaign was launched as `readiness-8c1dd46-full-01`.
Its outcomes belong to its own sealed evidence and local execution ledger; they cannot be
inferred from the six-gate result or cited before sealing and provenance verification.
Network Logon, disk pressure, failed UI delivery, sessions,
adverse bootstrap trials and seven-day endurance are not part of the six-gate result.
The operator explicitly deferred the Network Logon leg; it was not queued.

The published September 28 full run was also reauthenticated with the protected verifier:
12/12 PASS. This preserves that historical evidence for its original published bytes; it does
not transfer qualification to the corrected candidate.

## Independent review and follow-ups

At the owner's request, a separate Codex agent reviewed the complete `531b302..8c1dd46` diff,
callers, NTFS primitives, MCP assertions and this draft in read-only mode. No new critical defect
or MCP authority bypass was demonstrated. It reproduced a pre-existing P2: JSON containing only
an ActionId and Target synthesized a successful/completed action with a default timestamp.

Signed fix `ce3b14abe11e0121d65005d52a595d8877a88f49` requires the six historical non-optional
constructor fields when reading. Five assertions failed before the fix; all nine shape tests and
81 Response tests pass after it, with build/format. Historical Phase/undo defaults and explicitly
present zero/false values remain valid. The reviewer checked the original writer's six-field schema
at `d855335` and independently confirmed this compatibility and the corruption/recovery path.
Field presence does not prove that editable records are authentic or semantically consistent.

Signed test follow-up `fcbb3827d2a821e8780eac219126b2f361bfc913` bounds stalled-body tests with a
five-second watchdog. EOF cleanup runs only after assertions or failure; it cannot set the
cancellation oracle. The shorter HttpClient.Timeout case is added. Baseline 9 boundary/178 Core
and final 10/179 pass, with build/format; the reviewer confirmed the failure/cleanup equivalence.
Production HTTP code is unchanged by this test-only patch.

Harness sessions: shape `57f98d9b-1cb1-4fee-a483-f77aa0ca4c34` (ready_for_ci), watchdog
`1bc975ef-e066-4018-ad4a-b0b87bf2e44f` (needs_human_review: changed assertions). These later
bytes need their own protected CI and candidate qualification; the `8c1dd46` VM result is not
transferred. Rotation/undo with two concurrent writer processes remains an explicit missing proof.
A suspected sharing-lock RuleStore counterexample was withdrawn after checking attribute-only
acquisition versus opening data; it was not used to justify a speculative change.

The initial operator draft session `22a9f25a-07e5-4b5d-a08e-b886928af198` was superseded after
evidence edits invalidated its green fingerprints; its blocked finish remains recorded. The final
checks in `7eda1365-e670-4df2-a9cf-75dc06b66980` passed (3,688 tests, ten gates), but finish was
blocked by a shared Jev configuration change. Fresh clean-baseline closure uses
`f113351a-1577-4580-831c-d5084a1c76b0`. The router/local ledgers retain actual reports,
fingerprints and CI status; AI review neither overrides old blockers nor constitutes human approval.

## Proposed target for the next privileged harness change

This is an acceptance protocol, **not an implemented or executed campaign**. The existing driver
has a 480-minute timeout and no fault/soak gate. New instrumentation and a suitably bounded
long-run driver need their own red/green checks, review, signed revision and independently
authenticated protected installation. Never elevate a script from the user-writable checkout.

| Leg | Injection and required oracle |
|---|---|
| Storage failure | Use only the disposable guest volume containing the actual journal/baseline. Prove the volume identity, no host/shared-folder mapping, bounded VHD growth and adequate host reserve before allocating. Record a genuine allocation/write disk-full error; an ACL denial or sharing lock is a separate control. Keep evidence on a second unsaturated guest volume. Capture health, pending counts, baseline and journal before/during/after failure. |
| Arrival delivery | Seed a healthy baseline, fail durable journaling, then inject 4,098 unique harmless persistence identities. No undelivered identity may become silently known. Observe notification/storage faults and retry exhaustion honestly. After freeing space, exercise explicit retry and a separate dashboard process restart; prove effective delivery or explicit outstanding coverage. |
| Coverage gain | Establish an unreadable disposable enumerator location, place 4,098 identities, then restore readability while the journal fails. The gain has 4,096 listed plus two unlisted identities. Verify the old baseline remains protected while the gain is pending; recovery/restart must report the gain including its overflow count. This is distinct from ordinary arrivals. |
| UI failure | Separately test suppressed notifications, blocked dispatcher and process termination before/after a durable journal write. A rendered balloon is not the durable acknowledgment contract. Correlate journal/health/baseline using unique probe identities; accept at-least-once repetition after crashes, reject silently baselined undelivered evidence. |
| Recovery/cleanup | Release only campaign-owned filler files and restore checkpoint after collection. Test exhausted-retry recovery, clean restart, journal bounds, effective state and no orphan ETW/service/process/probe. A missing oracle, timeout or forced termination is recorded explicitly; never convert it to a graceful-shutdown pass. |
| Journal writers | Two separate writer processes in the same session, store near rotation, concurrent append/undo. Reconcile every returned durable result with an independent bounded receipt trace and the expected retained window/undo state in serialization order. Distinguish legitimate retention eviction from lost writes; verify unique IDs, ordering and byte/line caps. Run other sessions separately; the current Local mutex is not an intersession guarantee. |

Abort before injection if the guest/volume/checkpoint identity is uncertain, a path is a reparse or
host share, evidence cannot be preserved, or projected VHD growth would breach the operator's
host reserve. Stop allocation at a reviewed byte/time bound even if the volume has not filled;
record NOT_RUN rather than filling another volume. A host watchdog must also abort on lost
heartbeat or reserve breach. Read the manifest and protect all paths before enabling the fault.
Never reboot the guest with planted autostarts present; remove only campaign-owned identities
before any OS restart. Preserve an independent bounded event receipt stream: the 500-entry alert
journal alone cannot prove delivery of 4,098 identities.

## Endurance profiles to freeze before execution

Use the two endpoint profiles and proposed acceptance budgets in the October 3 record: 4 vCPU /
8 GiB reference VM, 168 hours each, daily scan; personal 10 FS and 10 DNS observations/s with hourly
500/s bursts for 60 seconds; business workstation 100/100 with hourly 2,000/s bursts, plus a separate
two-user session leg. This is a local workstation qualification, not fleet-management capacity.

Before starting, freeze the candidate/artifact hashes, VM image, provider configuration, seed,
operation counts, timestamps, injection mix, polling interval, deadlines and sampling-script hashes.
DNS generation uses an isolated local resolver; filesystem activity uses only a disposable corpus.
Measure the achieved rate, including generator failures, rather than claiming the requested rate.
Use monotonic latency timestamps and specify the percentile estimator. Collect per-second CPU,
private bytes, handles, threads, journal sizes and ETW/FSW loss/coverage counters; distinguish scans
and overload windows from steady monitoring. Track restarts/PIDs and cumulative reset counters.

Correlate separately planted Guardian alerts by unique IDs. FSW coalescing and a benign file change
do not imply one security alert per operation. Reconcile operation receipts, final monitored state,
provider loss diagnostics and actual alert IDs. Missing counter/oracle coverage leaves the relevant
claim unqualified. Stream measurements to protected, bounded evidence with explicit coverage gaps;
bounded product journals are not seven-day archives. Run a short pilot first, then fresh full-duration
campaigns without weakening the frozen thresholds. Neither profile has been measured yet.

## Owner handoff

The [draft PR #167](https://github.com/ClementG91/winsight/pull/167) contains the corrected product
and the full local test/CI trail. Owner review is still required, particularly A2 integration and
the broad initial readiness document whose Jev contexts exceeded the 20 KB limit, plus security
changes and guard assertions. Offering to review is not a recorded approval. No blocked historical
harness session was overridden. Governance decisions and any next privileged harness change remain
owner-supervised. Corrected distribution requires a new version and its own release inventory.
