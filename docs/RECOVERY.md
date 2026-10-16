# Recovery runbook

For when something is wrong now. Each section states the symptom, what is actually true underneath,
and the shortest safe way out.

Each section identifies whether a command changes state. Per-user Guardian history, rules and
response commands run as the affected user. Service install/uninstall and policy mutations require
an elevated trusted console; read-only service status does not. Examples using service executables
assume the install directory.

## First: get the ground truth

Before changing anything, find out what is really happening. The UI is a client; the service and WFP
are the truth.

```powershell
sc query WinSightFirewall
& .\winsight-firewall-service.exe enforce-status
& .\winsight-firewall-service.exe wfp-status
```

| Output | Meaning |
|---|---|
| `sc query` → error 1060 | The service is not installed. Current dynamic-session filters cannot remain active, but run `wfp-status` to detect residue from a pre-dynamic WinSight version. |
| `wfp-status` → all `absent` | WinSight has no WFP objects. Any blocking you see is not WinSight's. |
| `wfp-status` → `provider: present, sublayer: present` | WinSight is armed. |
| `enforce-status` → `AuditOnly` | The persisted intent is not to filter. |

**If `wfp-status` reports everything absent, WinSight is not blocking anything.** Look elsewhere -
Windows Defender Firewall, a VPN client, or a proxy.

## An application cannot reach the network

1. Confirm it is WinSight:

```powershell
& .\winsight-firewall-service.exe wfp-block-status "C:\path\to\app.exe"
```

`[FW_APP_BLOCKED]` means WinSight is blocking it. Anything else means it is not.

2. If it is WinSight and you need it back now: **dashboard → Emergency disable**. That lifts every
   WinSight filter and returns to audit-only.

   If emergency disable itself fails - it refuses when the policy directory under
   `%ProgramData%\WinSight` is no longer trusted (changed owner or ACL, or a reparse point) - stop
   the service from an elevated prompt: `Stop-Service WinSightFirewall`. Its filters are dynamic
   WFP objects and are removed when the service's engine session ends, and a service started from
   untrusted storage applies no filter. Then repair or remove the directory before re-arming.
3. If you only want that one application unblocked, change its policy in the dashboard instead -
   emergency disable is a blunt instrument and turns off all protection.

Then verify, rather than trusting the dialog:

```powershell
& .\winsight-firewall-service.exe wfp-status
```

## The whole machine lost network access

WinSight blocks **per application**. It does not have a machine-wide cut, and the per-app scoping is
verified on real hardware - a blocked application returns http 000 while an independent control still
returns 200 ([record](validation/2026-07-23-wfp-qualification-f0a3f16.md)).

So a total outage is probably not WinSight. Confirm in seconds:

```powershell
& .\winsight-firewall-service.exe wfp-status
```

All `absent` means WinSight owns no filters at all. Stopping a current service closes its dynamic WFP
session and is safe and reversible; verify the postcondition rather than assuming it:

```powershell
sc stop WinSightFirewall
& .\winsight-firewall-service.exe wfp-status   # must be all absent
```

An all-absent result after the stop removes WinSight from the picture entirely. A present object is
legacy residue or a defect and should be handled by the elevated `uninstall` recovery path below.

## The dashboard says the service is unavailable

The dashboard is an unprivileged client. "Unavailable" means it could not complete an authenticated
exchange, which has three ordinary causes:

1. **The service is not running** - `sc query WinSightFirewall`, then `sc start WinSightFirewall`.
2. **The service is not installed** - error 1060. See [`ADMINISTRATION.md`](ADMINISTRATION.md).
3. **You are running as a network logon** - the pipe denies the Network SID by design and always will.

Reading status does not require elevation. **Changing policy does**, and an unelevated administrator
is refused exactly like a standard user, because Windows hands out a filtered token. That is
intended, and it is verified: an unprivileged caller reads status and is refused the mutation
([record](validation/2026-07-23-ipc-boundary-c9177cd.md)).

## The service refuses to install

The service will not register from a location an unprivileged user can write. The refusal always
names the reason:

| Code | Meaning | Fix |
|---|---|---|
| `[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]` | A path component is writable by a non-privileged principal | Install under `C:\Program Files\...` |
| `[FW_INSTALL_PATH_UNTRUSTED_OWNER]` | The binary is not owned by SYSTEM or Administrators | Reinstall from the official package |
| `[FW_INSTALL_PATH_REPARSE_POINT]` | A component is a junction or symlink | Use the real path |
| `[FW_INSTALL_PATH_MISSING_COMPONENT]` | A directory in the path does not exist | Check the path |
| `[FW_INSTALL_PATH_IDENTITY_CHANGED]` | The file changed between inspection and use | Retry; if it repeats, treat it as hostile |
| `[FW_INSTALL_PATH_OUTSIDE_MACHINE_DATA]` | Storage path outside the trusted machine-data root | Use the default location |
| `[FW_INSTALL_PATH_INVALID]` | The path is malformed | Check the path |
| `[FW_INSTALL_PATH_INSPECTION_FAILED]` | Inspection could not complete | Check permissions and the event log |

Diagnose any path without changing anything:

```powershell
& .\winsight-firewall-service.exe install-path-trust-check "C:\some\path\winsight-firewall-service.exe"
```

## The status says Degraded

`Degraded` means: enforcement is the persisted intent, but the live WFP state could not be verified
exactly. **It is an honest answer, not a malfunction** - the alternative would be claiming `Active`
without proof.

```powershell
& .\winsight-firewall-service.exe wfp-status
```

- Objects present but incomplete → emergency disable, then re-arm.
- Objects absent → the machine is not filtering despite the persisted intent. Re-arm from the
  dashboard, and treat it as worth reporting.

Never assume `Degraded` means "probably fine".

## The policy store is corrupt

WinSight recovers to audit-only on its own and reports a diagnostic, rather than partially honouring a
file it cannot parse. The machine is **not filtering** in that state.

To reset deliberately, with the service stopped:

```powershell
sc stop WinSightFirewall
Rename-Item "$env:ProgramData\WinSight\firewall\policies.json" "policies.json.bad"
sc start WinSightFirewall
```

Keep the `.bad` file - it is evidence if the corruption was not accidental.

## Restore something Guardian quarantined

A Guardian Block moves the entry to a per-user quarantine under
`%LOCALAPPDATA%\WinSight\quarantine`. The Block confirmation shows the exact command that undoes it;
if you no longer have it, find the block's id with `winsight actions` (the history is kept in
`%LOCALAPPDATA%\WinSight\action-journal.jsonl`) and run `winsight restore <id> --confirm`.

To be alerted again about an item you allowed, list the rules with `winsight rules` and run
`winsight revoke <id> --confirm`. An allowed item is never hidden: its arrivals still appear in
`winsight alerts` as "not announced", naming the rule.

Restore rewrites the original
registry value (with its kind) or startup file **only if that location is still free**; if something
else has taken the name, WinSight leaves the new occupant alone and reports the conflict, so restoring
never overwrites a legitimate replacement. A quarantined payload is stored under the user's own DACL;
deleting the quarantine directory discards the ability to restore.

## Response audit storage needs attention

Run `winsight actions` as the affected user, in an ordinary console. The per-user files are under
`%LOCALAPPDATA%\WinSight`; elevating as a different account inspects a different profile. CLI,
dashboard history and MCP use the same read-only coverage report. Reading never repairs storage.
The next response writer performs bounded recovery under the storage lock.

Every response requires a durable Prepared record before it changes anything. A successful machine
change whose Completed write failed is reported separately; do not automatically replay it. Inspect
the effective process, persistence entry or rule before deciding whether to retry. A pending recovery
counter can coexist with a durable write; it is not evidence that the machine change failed.

| Journal result / coverage | Meaning and recovery |
|---|---|
| `Appended`, `Rotated`, `Updated` | The requested write is durable. Inspect history coverage separately; retention is bounded. |
| Missing active journal | A new journal can be created when its ordinary local parent is writable. Existing evidence is still inspected; absence of the active file does not prove absence of prior history. |
| Malformed or torn records | The reader reports incomplete coverage. Small damaged tails remain intact, separated from later appends by a newline. A required rewrite preserves raw evidence within the documented budgets. Retry after resolving a transient storage failure. |
| `RecoveryRequired` / oversized legacy state | The next writer attempts to normalize the active journal and evidence, preserving the newest raw 16 MiB tail and reporting discarded prefix bytes. Access and storage must still permit recovery. Before allowing maintenance, make a separate private backup if the entire legacy file must be retained. This backup is outside the automatic storage budget. |
| `EvidencePreservationFailed` | A required journal rewrite cannot safely preserve raw evidence or assess the bounded ring. All four slots must be ordinary readable local files or confirmed absent before allocation or eviction; a directory, reparse or read denial is uncertain evidence, even if another slot is free. Check free space, file permissions and sharing; close conflicting handles, then retry. Preserve unexpected directories/reparses separately with their identity and contents before an operator repairs the slot path. Do not delete evidence or the index to clear the diagnostic. |
| `EvidenceRecoveryBlocked` | A pending eviction/trim or its intent metadata could not be read, published or finalized safely. New append/undo is refused because the writer cannot exclude unfinished recovery. Keep journal, slots, index and staging files together; inspect `winsight actions`, restore local read/write access and space, close conflicting handles, then retry. Unrecognized readable metadata is preserved and blocks every mutation; follow the operator recovery procedure below. No discard amount or digest is invented for preserved bytes. Unreadable metadata must never be assumed empty. |
| Unusable archive without a pending intent | A healthy append/undo proceeds; coverage still marks unavailable or oversized evidence as a current problem. Optional archive migration is attempted before writing, but a read/acquisition failure without a durable intent does not block the healthy journal. Once a trim intent is durable, an unresolved publication blocks the next mutation. A damaged rewrite that needs preservation uses the stricter ring check above. |
| `RotationFailed` | Atomic replacement did not complete. The old source remains available. Resolve sharing/ACL/disk-space problems and retry. A pre-existing `.winsight-journal.tmp` is preserved and requires the staging procedure below; its name does not prove ownership. |
| `Unavailable` | The exact ordinary local file could not be acquired or the writer lock was unavailable. Reparse points and unavailable cloud placeholders are refused. Restore the intended ordinary file/permissions or availability, then retry; do not bypass the acquisition checks. |
| `InvalidRecord` | The action identity or enum/input is invalid. Inspect the supplied action; increasing storage budgets is not a repair. Product labels are centrally bounded with a truncation marker and digest; full functional rule/quarantine keys remain intact. |
| `TargetNotFound` | No retained completed target could be annotated. Retention may already have removed it. Inspect the actual action and its undo records; do not invent a successful annotation. |
| `RetentionLimit` | The undo annotation cannot fit without evicting its own target. Publication is refused and the original journal is unchanged. An externally supplied undo ID need not have a record; inspect what is actually available. |
| Pending eviction/trim | A durable recovery intent is awaiting completion or verification. Leave the source, evidence, index and fixed staging files together; a subsequent writer resumes it when access and staging allow safe publication. Restore transient access before retrying; a pre-existing staging file requires the procedure below. |
| Unknown counters / unverified loss | Exact earlier loss cannot be established, for example after present but corrupt/unreadable metadata, saturation or an unexpected source replacement. History explicitly reports that uncertainty and available digests. A genuinely absent index initializes a new accounting state; this does not establish absence of historical losses. Never delete the index to clear a diagnostic. A zero counter with unknown accounting is not proof of zero loss. |

The normalized active journal is capped at **16 MiB / 10,000 physical lines**; rotation retains
complete available action groups within **8 MiB / 5,000 physical lines**. Writers preserve the newest
Prepared and Completed phases and their timestamps for retained actions. Ordinary history returns
the latest logical state. Original-to-undo annotation is best-effort after a durable undo completion;
a failed link does not reverse the machine change, and both records are not guaranteed to remain.
Unknown newer journal enum values are treated as malformed opaque evidence, not executable actions.

Four raw-evidence slots are capped at 16 MiB each, with an 8 KiB index. The normalized live-file bound
is **80 MiB + 8 KiB**; including all fixed staging names gives a conservative **160 MiB + 16 KiB**.
This covers these journal-managed files, not quarantine, other WinSight state or separate backups.
Externally oversized legacy sources/archives can exceed the bound before maintenance. When the bounded
budget discards evidence, history names the reason and exposes counters or explicit uncertainty.

`winsight actions` separates current coverage from historical accounting. An unreadable journal,
malformed records in the inspected tail, the physical read budget, pending recovery, inaccessible
evidence/metadata or oversized state is **Notable**. Historical archives and loss/unknown-prior
counters alone are **Info**, with their counters, reasons and configured journal/index/slot paths;
they do not claim that older history was complete. The normal CLI exit code is `1` when a Notable
item exists and `0` when only Info is present, including historical accounting. A recorded failed
response can independently remain Notable. Reading a requested shorter list is not itself a physical
coverage failure. CLI/MCP reads never acknowledge, delete or reset accounting. No acknowledgment verb
is introduced; the archives and counters remain available without requiring deletion to clear a
current-coverage diagnostic.

If the index can be acquired but its DATA read fails, the readable journal entries remain visible.
Coverage marks the metadata unavailable, recovery/verification pending and prior counters unknown;
zero-valued fields are not proof of zero historical loss. Append and undo refuse with
`EvidenceRecoveryBlocked` until ordinary index access is restored. Inspect its permissions, local
availability and conflicting handles, preserve the index, then retry as the affected user. A
readable but unrecognized index is preserved and blocks every mutation as described below; an ACL
entry alone is not proof that Windows actually refused a DATA read.

### Unrecognized intent metadata and first publication

The index is recognized only when its decoded property names are unique and known, its nine legacy
fields are present and correctly typed, and its bounded counters and intents are coherent. The seven
trim fields must be absent together or present together. Inactive intents cannot contain stale
pending amounts/identities, and simultaneous trim and eviction intents are refused. A valid legacy
index remains supported; recognized pending recovery still resumes and counts loss exactly once.

A malformed, interrupted, empty, oversized, future-version, unknown-field or ambiguous index is
**unrecognized**. Append and undo return `EvidenceRecoveryBlocked`; no index, archive or history bytes
are overwritten or destructively resumed from those unknown instructions. Readable journal entries
remain visible. Coverage reports unrecognized metadata, recovery required and unknown accounting;
it does not invent `DiscardedMetadataBytes` or a discard hash for bytes that remain preserved. This
supersedes the former test/document contract that automatically discarded arbitrary malformed
metadata. Historical discard counters already present in a recognized legacy index remain visible.

Stop all writers across sessions, preserve and inventory the journal, all archives, index, sidecars
and staging with hashes, then determine which configured store owns each path. Prefer a compatible
version or reviewed complete backup. A real rule store at the index path must remain intact; choose
nonoverlapping store families instead. If deliberately rebuilding accounting after review, move the
unrecognized index intact to a new backup outside every store family, keep its hash/identity record,
and explicitly record that prior loss accounting cannot be established. A newly absent index does
not prove zero historical loss. Never edit a future index into version 1 or delete it to hide a gap.

Native confirmed absence permits only a first atomic publication **without replacement**. Both
index and rule-store initialization use that rule: a destination that appears after the observation
wins, and the losing publication preserves its bytes. The missing observation is not serialized and
becomes recognized only after successful durable publication. Existing recognized state retains
atomic replacement under its writer protocol; callers keep their default replacement behavior.
The complete application bundle must be rebuilt together for the updated Core method signatures.

Recognition establishes a format, not cryptographic ownership. Current metadata is revalidated
before replacement, but this is not a general compare-and-swap against actors outside the writer
protocol, copied recognized indexes or every alias between configured journals. Private state and
nonoverlapping configured families remain required. The correction closes the reproduced foreign
rule-store/index collision and their cooperative first-publication race; broader alias and external
actor qualification remains separate.

Structurally valid rule entries whose scope, decision or duration is unknown to this version are
retained as their exact UTF-8 object bytes across neighboring writes. They are never matched or
returned as active rules, even if their duration would otherwise appear permanent. Their separate
`retainedUnsupportedEntries` count is informational; it is not an invalid-entry removal count.
Use a compatible version to apply those semantics. A new rule cannot replace an unknown entry
with the same ID (`UnsupportedIdentityCollision`). Explicit `winsight revoke --confirm` can remove
that ID through the existing journalled response path; MCP cannot perform this mutation.

Null, keyless, incomplete, mistyped or ambiguously duplicated semantic fields remain invalid:
reads report them as current coverage problems, and a successful write removes them visibly.
Decoded duplicate field names are rejected, including escaped spellings. Fully understood
Once/UntilReboot/UntilProcessExit rules remain unstorable; any entry containing an unknown enum
stays opaque and inactive if structurally valid. Timed entries still require an expiry.
Known entries also retain their raw extension fields. All retained entries count toward 8192,
and their complete raw bytes count toward the 8 MiB output budget; a writer never discards them
to make room. This corrects the previous unknown-enum test contract that treated future entries
as invalid and expected their removal. Genuinely invalid-entry assertions remain in place.

Atomic journal publication creates its fixed `.winsight-journal.tmp` with native create-new semantics.
It never removes or overwrites a pre-existing entry at that name. Such an entry may be another
configured journal, unrelated data, or a crash remnant; neither its suffix nor plausible partial
contents prove ownership. A blocked undo/rotation reports `RotationFailed`; required evidence
publication reports `EvidencePreservationFailed`, or `EvidenceRecoveryBlocked` while resuming an
already durable intent. The original source and unknown staging bytes remain available.

After a crash, one fixed staging file per destination may therefore require operator recovery.
Stop every writer in every session, inventory and preserve the journal, all slots, index and staging
together with their hashes and identities, and inspect which configured store owns each path.
Keep any actual second journal at its configured location and choose nonoverlapping paths for the
stores. For a reviewed crash remnant, move it intact to a reviewed backup location outside every
store's derived paths, retain the hash/identity record, then retry as the affected user. Never delete
unknown staging to retry. This is a deliberate availability limitation: automatic crash cleanup
cannot safely claim ownership of arbitrary pre-existing bytes. Normal failures clean only the
freshly created exclusive staging handle; the fixed-name storage budget above remains unchanged.

Do not delete `.corrupt*.jsonl`, `.evidence.json` or recovery staging files to retry a response. Preserve
them together if storage is genuinely lost and a reviewed backup must be recovered. Stop all WinSight
writers first, including older versions in every Windows session: current writers use persistent
per-user adjacent `.lock` files; old `Local`/`Global` mutex writers do not participate in that protocol.
Never remove or rename a live `.lock`: that can split serialization into two distinct files. Readers
only open existing locks. A legacy lockless read retains a directory bootstrap gate and a DATA read
lease through coverage; a first writer waits before initializing the sidecar. The gate is released
before any mutation after sidecar acquisition. Bootstrap needs directory listing access and may
wait on a competing directory DATA handle; close that operation and retry a `LockTimeout`. Established
sidecars use no directory DATA gate. Every legacy snapshot still verifies sidecar absence at acceptance.
Same-session tests do not qualify cross-session or
cross-integrity behavior. See the [regression record](validation/2026-10-05-readiness-regressions.md).

## Response rules are malformed or unavailable

Run `winsight rules` as the affected user. `response-rules.json` lives beside the journal. The report
includes typed storage status and ignored-entry counts. An unreadable suppression store yields no
honored Allow rules: alerts continue, while new Allow/Revoke writes are refused. Missing is distinguished
from access denial on the same file acquisition: only confirmed absence permits interpreting a file
that could not be opened as an empty store. A readable valid store with no active rules is also healthy.

| Rule status | Meaning and recovery |
|---|---|
| `Loaded`, `Missing` | The store was read, or its absence was confirmed. A missing file can be created on the next successful write. |
| `Written` | Flushed atomic publication succeeded. Invalid individual entries are removed only by this successful write. |
| Ignored invalid entries | Null/keyless, incomplete or unsupported individual rules are never honored. Valid neighbors remain usable. The read preserves all bytes; inspect the ignored count before authorizing a write that drops those entries. |
| `TargetNotFound` | The rule is absent from a readable store. This is distinct from a failed read or failed revocation. |
| `InvalidRule` | A proposed rule lacks a supported identity/key/scope/decision/lifetime or required timed expiry. Correct the input; never interpret unknown values as an Allow. |
| `InvalidJson`, `InvalidFormat` | The versioned envelope is malformed. The original file is preserved and no rules are honored or overwritten. Use the deliberate recovery procedure below. |
| `UnsupportedVersion` | This version cannot interpret the file. Prefer the compatible WinSight version or a reviewed backup; a downgrade does not silently overwrite newer policy. |
| `ByteLimit` | The unchanged 8 MiB file budget is exceeded. Recover a reviewed in-budget backup; no automatic overwrite of the oversized policy occurs. |
| `RuleLimit` | The unchanged raw 8,192-entry budget is exceeded. Revoke from a readable in-budget store or recover a reviewed backup. Replacing the same ID at capacity remains possible. |
| `Unavailable` | Restore ordinary local-file availability, permissions, free space and sharing, then retry. A placeholder/reparse refusal is not a missing store. |
| `WriteFailed` | Atomic replacement failed. Preserve the old file, resolve the transient cause and retry. Failed Revoke is never reported as successful removal. |
| `LockTimeout` (journal or rules) | Another operation holds the persistent `.lock`. Wait for it to exit and retry. The existing 30-second budget is unchanged; the OS releases its handle after a crash. Never delete a live sidecar. |
| `UnsafeLockPath` (journal or rules) | The sidecar or parent is a directory, reparse, non-local or inaccessible path. Stop all writers across sessions; inspect the exact adjacent `.lock` and its parent without following reparses. Preserve an unexpected entry separately before repairing the state directory and its per-user ACL. Never replace it while a writer may run. |
| `LockUnavailable` (journal or rules) | Opening the sidecar failed, or a writer initialized it during a legacy read. Retry a transient read; otherwise inspect sidecar permissions and sharing as the affected user. A missing sidecar alone is permitted for read-only legacy inspection. |

For a malformed or incompatible envelope, close every dashboard/CLI writer for this user and retain
an exact private copy with its SHA-256 before changing the original. Prefer restoring a reviewed
compatible backup. If deliberately starting a new empty suppression policy, move the original to a
**new, nonexisting backup name**, preserving its bytes and ACL, then leave the active path absent.
The next authorized write creates the new versioned store. Verify `winsight rules` as this same user;
review which suppressions were lost and re-add only intended rules. Never edit an unknown-version
file into version 1 or discard evidence to make it appear readable.

Allow rollback reports confirmed absence as failed/non-reversible, a confirmed remaining active rule
as partially applied, and unreadable state as unconfirmed. Check the actual rule status before retrying
an Allow or Revoke. The process/Guardian responses and the machine-wide firewall policy are separate
stores; repairing per-user suppression must not change service policy.

If Allow's completion cannot be journalled, automatic rollback removes only the exact single rule
object that the failed Allow wrote. Comparison, removal and the activity observation share one
writer lock. A replacement with the same ID, an opaque extension, changed object bytes (including
external reformatting) or duplicate IDs returns `TargetChanged`: the complete store is preserved,
the original rule is not returned as active, and the action remains partially applied and
non-reversible with its Prepared audit gap visible. No invalid neighbor is cleaned on this refusal.
Identity observation includes decoded ID properties in invalid entries before those entries are
filtered from active rules. A keyless or incomplete replacement is therefore a changed target,
and an invalid same-ID duplicate cannot authorize deleting the original or cleaning that duplicate.
An unchanged rule whose atomic removal returns `WriteFailed` is reported as remaining active only
if its supported semantics and the store clock confirm activity under that lock. This observation
does not prevent a later operator action from changing the store. Explicit journalled Revoke by ID
still removes all loader-retained matching entries when requested by the operator; invalid-only
records are ignored by that loader and do not become removable rules. Inspect `winsight rules` first.

### Journal filename family and archive order

The configured journal filename must contain at most **218 UTF-16 units** for writes. The longest
derived component combines a numbered archive suffix (16 units) and its fixed staging suffix
(21 units), within the Windows ordinary 255-unit component budget. This validates the normalized
filename, including supplementary characters counted as two units; it does not guarantee access,
validate every volume's limits, or canonicalize aliases/hardlinks into a shared lock identity.
Default filenames fit this budget. Append and undo report non-durable `PathTooLong` before creating
directories, locks, metadata or staging. Existing bytes remain intact.

Existing longer filenames remain available for bounded read-only history inspection, using an
ordinary local DATA read handle that denies simultaneous writes/deletes. Native local-file and
reparse protections still apply. The report separates write refusal from actual history coverage;
that refusal alone does not claim the readable history is incomplete. Representable metadata and
archives retain their real coverage/counters; auxiliary components beyond 255 units are uninspected
and accounting is marked unknown, without inventing discarded bytes or an access failure. Physical
history budgets and malformed-record reporting remain in force. Stop all writers across sessions,
inventory and preserve the entire family with hashes, then choose a reviewed shorter, nonoverlapping
path and transfer the preserved state consistently before retrying. Never truncate a configured
name or delete evidence just to clear this diagnostic.

Archive slots use cyclic replacement when all four are occupied. If an external operation removes
a slot, preservation fills an available slot before later cyclic replacement. Slot numbers are
therefore not a chronological order, and after a manual deletion the next victim is not guaranteed
to be the oldest surviving archive. No chronology is reconstructed from untrusted file timestamps.
Preserve and inventory all four slots together; deletion is not a supported recovery shortcut.

## Full removal

```powershell
& .\winsight-firewall-service.exe uninstall
sc query WinSightFirewall          # must be error 1060
& .\winsight-firewall-service.exe wfp-status   # must be all absent
```

Then uninstall the application from Settings, or run `unins000.exe` in the install directory.

If `wfp-status` still shows objects after uninstalling the service, that is a defect - capture the
output and report it under [`SECURITY.md`](../SECURITY.md).

## Nothing here helped

Collect, and open an issue:

- `winsight --version` and your Windows build
- `sc query WinSightFirewall`
- `enforce-status` and `wfp-status` output
- Whether the machine was armed, and what changed just before

If the problem is that WinSight **misreported its own state** - said filtered when it was not, or the
reverse - report it privately as a security issue rather than a bug. For a security tool that is a
vulnerability.

## Response coordination after the second review

N1 replaces the two PR-introduced `Global` mutex names with persistent adjacent `.lock` files.
The supported default state directory is per-user LocalAppData. Custom state paths must have the
same private access policy; a world-writable custom directory cannot isolate accounts. Native opens
reject network paths and reparses, hold the parent and a DATA read handle with `FileShare.None`, and
retry only sharing contention within the existing 30 seconds. Handles are crash-released; files are
never deleted. Readers create nothing and share the existing sidecar. Before a first writer creates
it, a legacy read holds an exclusive directory DATA gate and the data file against writes/deletes
through coverage. A first writer waits for that reader within its lock budget before initializing the
sidecar. Both open the sidecar relative to the acquired parent; the bootstrap gate is released before
any maintenance or mutation once a sidecar exists. Normal operations do not acquire that directory
DATA gate, so directory watchers cannot block established sidecar coordination. Bootstrap requires
directory listing access and can time out on an existing directory DATA handle; initialize only
after closing competing directory operations. These are typed lock refusals, never missing storage.

A SID-bound private namespace was considered. It requires additional boundary/DACL, namespace
handle-lifetime and cross-session interop to prove isolation. The file protocol reuses the existing
native local-file safety layer and Windows sharing enforcement. Taking the legacy `Local` mutex too
would reintroduce squatting; stop all older writers across sessions before upgrading instead.

The permanent N1 regression asserts successful actions/rule publication while a child holds both
former Global names with a restrictive DACL. It replaces the review probe's intentional defect
assertions. The original probe directory remains untouched. Tests that asserted Global naming or
held that mutex now assert/hold the sidecar, retaining their failure, timeout and recovery oracles.

### Named kernel object inventory against main 531b302

| Object | Introduced by this PR? | Remaining observation |
|---|---|---|
| ActionJournal / RuleStore Global mutexes | Yes; removed by N1 | Persistent per-user file coordination replaces them. |
| PersistenceBaseline Local mutex | Pre-existing; removed by baseline correction | Persistent adjacent file gate serializes complete snapshot publication; see migration limits below. |
| VirusTotal quota Local mutex | Pre-existing; removed by quota correction | Persistent adjacent file gate serializes admissions; see the migration limits below. |
| CanaryManifest Local mutex | No | Same-session predictable name; no intersession serialization. |
| CanarySession Local mutex plus GUID | No | Cross-session ownership observation may misclassify another session's live canaries. |
| Dashboard Local mutex and activation event plus SID | Pre-existing; trust correction added | Exact-handle current-user ownership and private DACL are checked before secondary decision, registration or signaling; see compatibility limits below. |
| Firewall pipe | No | Explicit DACL, network refusal, first-instance reservation and client SYSTEM-owner verification; prior squatting may deny startup but cannot authenticate a false SYSTEM peer. |

The remaining unchanged observations are residual risks from source review, not reproduced vulnerabilities
or a claim of qualification. They require separate scoped work; changing all of them inside N1 would
broaden authority and lifecycle behavior beyond the two PR-introduced response locks. A real
same-user second-session run and cross-integrity qualification remain NOT_RUN until measured.

### VirusTotal quota accounting and migration

The quota guard uses the persistent `<quota-path>.lock` sidecar across load, validation, rolling-window
normalization, admission and atomic publication. Only a busy gate is retried, within one two-second
acquisition wait budget. Synchronous native filesystem calls are not preempted by that budget. The
gate is closed after the transaction and its file remains on disk, including after a crashed holder.
No HTTP request runs while it is held. Construction normalizes the path without creating files;
admission may create ordinary missing parents and the sidecar. Primary and sidecar leaf names must
fit the filesystem component limit before either is created.

Only a native missing-state result permits initialization. An unreadable, non-local, directory,
malformed, incomplete or unsupported state refuses admission and preserves existing state bytes.
The former unreadable-state reset was reproduced in an owned temporary fixture with actual Windows
access controls: read refusal was not a missing file, replacement remained possible, and counters
at three were overwritten with one. The regression asserts those native preconditions before
asserting refusal. It does not use an API key or send a request to VirusTotal.

Recognized legacy JSON has exactly `recentRequests`, `utcDay`, `dayCount`, `utcMonth` and `monthCount`.
All fields are required, with strict types and spelling; duplicates (including escaped duplicates),
unknown fields, negative counters and invalid or mismatched calendar periods are refused. At most
64 recent timestamps are supported, so custom minute limits must be 1–64; daily and monthly limits
must be positive. Defaults remain 4, 500 and 15,500. The reader checks the acquired DATA length and
reads at most 65,537 bytes into a fixed buffer before parsing; the accepted physical limit is 65,536
bytes, including an optional single initial UTF-8 BOM. This bounds parser input, not total heap use
or operating-system prefetch. Existing valid rolling-minute and UTC day/month rollover behavior
is retained, including dropping future timestamps during normalization.

The original boolean API and four-field snapshot contract remain available. The additional status
overload distinguishes `Acquired`, `QuotaExhausted`, `LockTimeout`, `UnsafePath`, `StateUnavailable`,
`StateInvalidOrUnsupported`, `StateOverBudget` and `WriteFailed` (`Unknown` is the uninitialized enum
value). On infrastructure refusal, snapshot counts at the configured limits are conservative
placeholders: they are not measured consumption. Only acquired or exhausted states establish usage.
A file appearing after confirmed absence is preserved by no-replace initial publication. Failed
publication is never retried as a whole admission; the next attempt reloads accounting.

Stop every older WinSight quota writer in all relevant Windows sessions before upgrade or downgrade.
Older named-mutex writers ignore the file protocol, and the new gate does not make mixed versions
safe. The default location relies on the Windows user's private profile directory. Arbitrary custom
parents are not made private by this guard; it does not change their ACLs. All cooperating processes
must use the same canonical path. Physical aliases and use of the same API key from other users or
machines are outside this local coordination contract. Recognized existing-state replacement is
protected by that cooperating-writer gate, not a general compare-and-swap against older or malicious
writers. Two owned local-process writers and killed-holder recovery are local regression oracles;
they do not replace real cross-session and cross-integrity VM qualification.

### Guardian baseline coordination and migration

Guardian writes a complete baseline and its associated coverage in one atomic publication while
holding the persistent `<baseline-path>.lock` file gate. This coordinates cooperating writers using
the same canonical local path across Windows sessions. It preserves the complete-snapshot contract:
the last successful publication replaces the previous snapshot; independent snapshots are never
unioned. Serialization does not reconcile two monitors' independently computed delivery state.

Only sharing contention is retried, within one 30-second acquisition budget. Synchronous native
filesystem operations are not preempted by that budget. Encoding, coverage and publication run once
under the acquired gate; an uncertain publication is never retried inside the store. Handles are
released on success and failure; the sidecar remains on disk. Unsupported, unavailable or timed-out
coordination throws `IOException`, allowing the monitor to report persistence failure. Existing
input and encoded-format limits still refuse with `InvalidDataException`.

Construction normalizes the destination without creating files. Reads remain nonmutating and do not
create parents or sidecars. A writer may create ordinary missing parents and the sidecar, but refuses
before mutation when the primary leaf plus `.lock` cannot fit a filesystem component. The existing
native file layer rejects unsupported paths, reparses and network storage. This change does not
alter the baseline parser or turn unreadable storage into confirmed absence.

Stop older Guardian writers in every relevant Windows session before upgrade or downgrade: their
named mutex does not participate in this file protocol. All cooperating writers must use the same
canonical logical path. The default location relies on the private Windows user profile; arbitrary
custom parents are not made private or given new ACLs. Physical aliases, hostile same-user writers,
administrators and independent monitor state reconciliation are outside this coordination contract.
Owned local regressions cover a held sidecar, an incompatible former kernel name, failure release
and complete snapshot/coverage pairing. Real cross-session and cross-integrity VM qualification
remains separate and must be measured on the final revision.

### Dashboard instance and activation trust

The interactive Dashboard keeps its existing per-user, per-Windows-session `Local` names. New
mutexes and activation events have an explicit current token-user owner and a protected DACL granting
full control only to that user and LocalSystem. Every returned handle, including an already-existing
object, is independently checked before it can suppress a launch, register activation or receive a
signal. A supplied creation descriptor does not establish an existing object's security.

The security query reads only owner and DACL from the exact `SafeWaitHandle`, with one fixed 4096-byte
buffer and no growth, retries or SACL privilege request. A failed query, oversized or malformed
descriptor, wrong owner, missing/null/unprotected DACL, unsupported ACE or unexpected principal/right
is untrusted. The supported DACL consists of ordinary, explicit, full-control allow ACEs for the user
and LocalSystem (one ACE when the user is LocalSystem). No other object's owner or ACL is repaired.

An untrusted or inaccessible mutex permits an independent primary without the single-instance
guarantee. A trusted primary retains its mutex even if activation is unavailable or untrusted.
A secondary retains the verified mutex through its activation attempt, opens only an existing event
with read-permission and modify rights, and signals only a separately verified event. Missing or
untrusted activation can leave a secondary unable to raise a primary that is starting or stopping;
it never creates a replacement event. Failure to obtain a reliable current token-user SID also
permits an independent primary; a user name is not an ownership proof.

Stop and restart older Dashboard processes before relying on this guarantee. Their default owner can
be an eligible group and their DACL can differ from the private template; strict refusal can permit
a new independent primary while an old Dashboard remains. This deliberately favors monitoring
availability over trusting an unknown marker. The check is point-in-time ownership/access policy,
not authentication of a WinSight executable or window. Code running as the same SID, including at a
different integrity level, and administrators can lie about or change such objects; that threat is
outside this scoped guarantee. The existing callback shutdown behavior does not establish that all
already-running callbacks have returned.

Local regressions use owned random names and positively verified ordinary DACLs. The managed parser
also receives synthetic null, malformed and unsupported descriptor bytes; no native object with a
null DACL is created. The separate attempted native null-DACL diagnostic was rejected before any
creation, compilation or execution and remains unestablished. These controls do not qualify actual
foreign-account, cross-integrity or VM operation on the final revision.
