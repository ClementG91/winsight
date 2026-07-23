# Phase 2, outbound firewall design

Status: privileged trust-boundary hardening is implemented in code; native SCM, DACL,
multi-user pipe and WFP behavior still requires isolated-VM validation.

## Goal

Provide LuLu-style per-application outbound decisions through Windows Filtering
Platform (WFP), while keeping the dashboard unprivileged and preserving network
access if the service crashes or is upgraded.

## Components

1. The existing connection monitor discovers outbound connections and attributes
   them to an executable.
2. The dashboard presents `allow`, `block`, or `ask` policies keyed by canonical
   executable path.
3. A dedicated Windows service is the only process allowed to mutate WFP. Its mandatory
   `IWinSightWfpReconciler` boundary is reached only through authenticated local IPC.
4. WFP filters live in one WinSight-owned sublayer. Persistent user choices are
   stored separately and reapplied transactionally at service startup.

The shared `AppFirewallPolicy` and `OutboundPolicyEvaluator` contracts are
implemented and unit-tested. They intentionally use executable paths rather than
process ids or display names, which are transient or ambiguous.

## Implemented service foundation

### LocalSystem trust boundary

- Service registration inspects the executable and every existing ancestor immediately
  before the SCM call. Missing components, reparse points, owners outside the explicit
  SYSTEM/Administrators policy (TrustedInstaller is accepted only for system ancestors),
  unprivileged write/create/delete/replace rights, and indeterminate inspection deny the
  operation with a stable code and redacted message. The two denial points before SCM creation raise
  a typed `ServicePathTrustException` carrying `PathTrustCode`; the CLI maps it to one of eight fixed
  `[FW_INSTALL_PATH_*]` allowlisted codes. Unknown/`Trusted` denial values fail closed to
  `[FW_INSTALL_PATH_INSPECTION_FAILED]`. Generic install/SCM failures remain
  `[FW_INSTALL_FAILED]`; neither sink prints an exception message or path.
- ACL evaluation is deterministic and follows DACL order: an earlier applicable Deny ACE
  removes matching dangerous rights before a later Allow is considered, while a later deny
  cannot revoke rights already allowed. Exact SID and well-known broad-group applicability
  are resolved directly; arbitrary group expansion is injectable for tests, and unknown
  membership is never used to turn a dangerous Allow into trust.
- Inspection obtains `FILE_ID_INFO` from a no-follow `SafeFileHandle` with
  `GetFileInformationByHandleEx(FileIdInfo)`. The stable identity contains the 64-bit volume serial
  and the complete 128-bit file identifier, so it does not assume the accepted service path is NTFS
  or retain the legacy 64-bit ReFS blind spot. Failed, unsupported or partial queries deny
  inspection; there is no `BY_HANDLE_FILE_INFORMATION`/`Pack = 4` fallback. The blittable ABI is
  pinned directly: a 16-byte explicit-layout identifier made of two `ulong` values inside a 24-byte
  sequential `FILE_ID_INFO`, with the outer fields at offsets 0 and 8. Its fixed-width stable string
  includes all 192 bits deterministically.
- Ten non-privileged ABI and real-filesystem tests cover those sizes/offsets, unchanged identity,
  simultaneous distinct files and rename-aside/plant detection. One deterministic sentinel proves
  the exact 64-bit volume, `Part0` and `Part1` contributions to the fixed-width 192-bit string. The
  tests deliberately do not require a non-zero volume serial or assume that a deleted identifier
  cannot be reused later. The installer revalidates identities immediately before SCM use and after
  registration; storage guards similarly bind each load/save to pre-use metadata and
  post-open/pre-replace checks. A live adversarial replacement inside the remaining in-process
  inspection/SCM window is still an isolated-VM gate; the deterministic tests do not claim to close
  that race.
- SCM receives only the canonical path carried by the inspected evidence. Registration is
  behind a testable SCM boundary; if post-registration revalidation fails, deletion is
  verified. Every operation after Create, including description configuration, is inside
  the same checked rollback boundary; the seam makes no assumption that cosmetic setup
  cannot throw. Successful rollback and rollback failure have distinct stable states.
- The policy directory is canonically contained beneath ProgramData. Provisioning is
  separate from inspection; startup and every privileged load/write re-inspect owner,
  ACL and reparse state. Distrust is distinct from malformed JSON and denies policy I/O
  before any native WFP backend is constructed or used.
- Pipe authentication yields one of three capabilities: none, read status/policies, or
  mutate machine policy. Authenticated local standard users receive read access only.
  SYSTEM and an elevated Administrator token receive mutation access. Anonymous, guest,
  network and uninspectable identities are denied.
- One live service coordinator is the authoritative mutation boundary used by IPC and
  startup; it serializes policy changes and enforcement transitions. Native WFP creation
  is lazy and occurs only after a fresh trusted load. The pipe exposes explicit privileged
  enable and emergency-disable transitions; the service derives mutation capability from
  the connected client token. CLI mutation verbs stay disabled so they cannot bypass that
  boundary. The central mode gate prevents adding/applying filters in AuditOnly. The only
  AuditOnly mutation is idempotent WinSight-owned cleanup during emergency/disable, ordered
  before AuditOnly is persisted.
- Enforcement-side policy changes replace the complete native state from one complete desired
  snapshot, then verify provider, sublayer and every filter before state can remain active.
  Compensation reconciles the complete prior snapshot; rollback to AuditOnly enumerates and
  removes every WinSight-owned object, including orphans absent from the store. Failure of
  compensation is distinct from the initiating transition failure so operators cannot mistake
  divergence for a safe rollback.
- External failures use stable protocol/path codes and fixed messages. They do not expose
  attacker-controlled paths, ACLs, SIDs, policy JSON, or native exception text.
- IPC, CLI output and hosted-service logs are independent diagnostic trust boundaries.
  Hosted services never attach caught exception objects to log records; fixed allowlisted
  `FW_*` codes preserve observability without allowing providers to serialize nested
  native or attacker-controlled text.
- The durable mode is a requested configuration, not runtime proof. The pipe reports a bounded
  effective state independently: `Active` is set only after a fresh native inventory exactly
  matches the complete enabled-block set during the current service lifetime. Status re-verifies
  that inventory, so BFE loss, missing/extra filters or unreadable state becomes `Degraded`.
  Startup, transition, rollback, or persistence failure also becomes
  `Degraded` and never reports a block as active. Success and failure states are published inside
  the same serialized transition as the associated WFP and persistence work, before a status reader
  can acquire the transition lock. A successful explicit enable is the recovery transition. The
  dashboard localizes these states in English, French, and Spanish.
- Security codes are locale-invariant. This service surface emits codes rather than new
  ad-hoc English presentation; user-facing WinSight presentation continues to use the
  existing EN/FR/ES localization layer. The VM protocol must inspect affected presentation
  in all three locales without changing the underlying codes.
- Firewall IPC v3 binds paginated collections to a complete stateless snapshot. The dashboard
  probes read-only status in v3, then v2, then v1; it descends only when the authenticated peer
  closes before returning any response byte. A timeout, malformed/partial frame or generic I/O
  fault never downgrades or caches a version, and no mutation is replayed. v2 carries runtime
  enforcement proof but no snapshot metadata; v1 has neither. A new service emits their exact
  strict wire shapes and returns a list to v1/v2 only when it fits in one complete page. A v1
  enforcement response is projected as `Degraded`, never filtering-active.
- The pipe name is not treated as server identity. Before writing any request, the client reads
  the connected pipe object's owner and requires the LocalSystem SID; unreadable or different
  ownership fails closed with a fixed diagnostic and cannot trigger v1 fallback. Every decoded
  reply must echo the exact request id and negotiated version before it can be used or cached.
  The service ACL explicitly assigns LocalSystem as owner and reserves `FirstPipeInstance` once
  for the listener lifetime, so a pre-existing squatter prevents startup rather than receiving
  dashboard traffic. The listener announces readiness only after this reservation succeeds.
- The single pipe instance applies independent bounded deadlines to reading the initial request
  and writing the completed reply. Those I/O deadlines release a silent client and permit the
  next connection; they never cancel the intervening dispatcher/WFP transition.
- A v1 response sent by a new service projects `Enforcement` only when the current effective
  state is `Active`. `AuditOnly` and `Degraded` both project audit-only/non-enforcing, protecting
  older dashboards that only understand the legacy desired-mode field.
- Every successful v3 list page repeats the uppercase SHA-256 version and count of the full,
  deterministically ordered validated collection. Continuations supply that version. The service
  recomputes it without retaining attacker-fillable snapshot state and returns `SnapshotChanged`
  before slicing when the collection changed. The dashboard requires stable version/count, exact
  offset progression, unique paths, bounded global counts and exact terminal count; any mismatch
  makes the whole view unavailable rather than presenting a plausible partial list.
- SCM boot persistence is part of the same serialized coordinator transaction as durable intent
  and WFP. Startup with desired Enforcement and explicit enable both require auto-start before
  filters can become `Active`. A failed enable removes partial filters, persists AuditOnly and
  restores demand-start. Emergency disable removes owned filters, persists AuditOnly, then restores
  demand-start; if that last SCM operation fails, filters remain off and AuditOnly remains durable,
  but runtime status becomes `Degraded` and the transition fails. It never reapplies filters.

### Native qualification protocol

- `Test-WfpValidation.ps1` is an isolated-VM protocol, not a production mutation interface. It
  requires a clean snapshot with no pre-existing WinSight service. Path trust stages only a
  user-writable sentinel as data, then the already protected candidate executes
  `install-path-trust-check <sentinel>`. That read-only command shares Install's inspect+revalidate
  primitive, emits only `[FW_INSTALL_PATH_TRUSTED]`/0 or one closed denial/1, and cannot call SCM/WFP
  or execute/load the sentinel. No staged service executable or DLL is launched. The candidate's
  provenance, protected deployment and immutable dependencies are an out-of-band operator trust
  root, not a self-proof and not an invented ProgramData executable restriction.
- After the probe, the protocol installs the requested candidate and verifies that SCM's canonical
  binary path plus `run` verb exactly match `-ServicePath`. Every elevated OS executable is resolved
  by protected absolute System32 path: `sc.exe`, `curl.exe` and
  `WindowsPowerShell\v1.0\powershell.exe`; ambient `PATH` is never consulted.
- Each native exit code remains paired with visible normalized output. The PowerShell adapter turns
  `ErrorRecord` into its message, collects with `Out-String`, and trims/prefixes lines for display;
  this is normalized presentation rather than the original native byte stream. Provider, sublayer and permit-filter state is
  parsed as an exact three-field value; mixed/partial state and non-zero native exits fail. Curl
  success and blocking each require the expected HTTP code *and* exit code.
- No manual arming prompt is reachable after a failed pre-arm check or failed connectivity baseline.
  `-SkipEnforcement` skips WFP arming only: in the VM it still installs/starts the candidate, then
  stops and uninstalls it and requires SCM error 1060. It is not a machine-read-only mode. The skip
  path requires exactly 16 checks and the full path 25. The normal non-privileged
  `ContractSelfTest` passes 24/24; its deliberate lifecycle-order negative control exits 1. The
  former 14/14 and the first local report based on it are invalid and non-qualifying. The
  intermediate 15/15 was a transient development count and is not evidence.
- One `New-ValidationAdapter` constructs the commands, staging, all three lifecycle polls and
  workflow operations. Real and scripted modes provide only elementary host effects. Scripted
  effects consume a closed exact ordered queue and reject an unexpected path, argument, order,
  cardinality or result type; they cannot return a precomputed `PollRunning`, `PollStopped`,
  `PollAbsent` or any other business decision. Running, Stopped and SCM-absent matrices therefore
  traverse the same production adapter, including delayed transitions, timeouts, exact ten-attempt
  bounds and the rule that uninstall is unreachable before Stopped. Effects still produce zero
  success values and decisions exactly one value of the expected type.
- Direct mutation refusal is exactly `[FW_DIRECT_MUTATION_DISABLED]` with exit 1 and is followed
  immediately by an exact absent/absent/absent WFP inventory. Enforcement status, WFP self-test and
  block-status each require their complete fixed output shape and exit code. System32 curl and the
  separate System32 Windows PowerShell HTTP control both require 200/exit 0 before arming; when curl
  is blocked only its exact 000/non-zero result is accepted while the control stays 200/0. Both must
  return to 200/0 after rollback.
- Cleanup replaces fixed sleeps with bounded locale-invariant stopped/absent polling. The full flow
  reaches uninstall only after emergency disable reports AuditOnly, the exact WFP tuple is fully
  absent and target connectivity is restored. If any rollback proof fails, uninstall is forbidden
  and the operator is directed to restore the clean VM snapshot.
- The same injected bounded polling primitive owns delayed Running, Stopped and SCM-absence
  transitions with exact attempt limits. StartPending is not an immediate failure, and uninstall is
  never reached before Stopped.
- `FirewallServiceCommandHost` is the single public CLI composition route. It owns parsing, routing,
  arity, fixed diagnostic/exit mapping and `TextWriter` channel selection. `Program` constructs the
  Windows capabilities, invokes `Execute` once and consumes its parsed verb/handled/exit outcome
  without a parallel Install or path-probe route. The probe handler receives only
  `IServicePathTrustInspector` and directly invokes the shared inspect/revalidate primitive; it has
  no install/elevation/process-path/SCM/WFP capability. Portable tests call this same public
  `Execute` with recording dependencies for trusted, eight-denial, invalid-arity and unexpected
  failure cases. A non-privileged subprocess smoke traverses the real `Program` root and proves that
  invalid probe arity yields exact inspection-failed stderr/exit 1 without inspection or machine
  mutation.
- The 2026-07-23 x64 transcript from script revision `76b5481` is historical observation only. Its
  reported 18/18 cannot qualify a production candidate because the old predicates could accept
  mixed WFP state, skip a failed probe, suppress visible native output and observe a different SCM
  binary. No corrected candidate-bound x64 or native Arm64 run has been executed.

Qualification status remains explicitly `NOT_RUN`/`BLOCKED` pending human execution in isolated
VMs: the corrected strict candidate-bound x64 rerun; native Arm64; real SCM lifecycle and
no-call-on-denial; owner/DACL/nested-reparse/live-TOCTOU; standard/elevated/SYSTEM multi-user pipe
tokens; native WFP enumeration/startup recovery/rollback; IPv4/IPv6/DNS/DHCP/loopback connectivity;
and EN/FR/ES human presentation. Local and scripted checks cannot convert any of these to PASS.

- `FirewallPolicyStore` persists a schema-versioned snapshot through a flushed
  temporary file and atomic same-volume replacement. It canonicalizes and
  deduplicates paths, bounds the file to 1 MiB and 4096 entries, rejects unknown or
  duplicate JSON members, caps cumulative path bytes before serialization and
  refuses reparse-point storage.
- Enforcement values require an explicit service-side gate. `LoadOrAuditAsync`
  converts corrupt, inaccessible or unsafe state to an empty audit-only snapshot;
  cancellation is never swallowed.
- `FirewallProtocolCodec` frames strict JSON behind a four-byte little-endian length
  capped at 64 KiB. It validates the exact version, non-empty request ID, command
  payload shape, canonical paths, enums and response invariants. v3 policy/pending listing is
  paged at no more than 128 entries per frame and bound to the complete snapshot digest/count;
  v1/v2 serve one complete page or fail explicitly.
- `AuditOnlyFirewallEngine` remains a non-mutating library/test implementation. It is not a
  production service fallback: the coordinator requires `IWinSightWfpReconciler` and constructs
  it lazily only after a fresh trusted load requires exact reconciliation or owned cleanup.
- `FirewallRequestDispatcher` turns a validated request into an effect against the
  store and engine. An unauthenticated caller only ever receives `Unauthorized`; store
  or engine faults collapse to `InternalFailure` with no exception text on the wire;
  and only the explicit, capability-gated `EnableEnforcement` command promotes the
  persisted mode. `EmergencyDisable` always returns the machine to audit-only, even from
  a corrupt store.
- `FirewallConnectionHandler` serves one authenticated request/response exchange over
  any duplex stream, so the logic is tested without a pipe or elevation.
- `NamedPipeFirewallServer` hosts the endpoint over a hardened local pipe.
  `FirewallServiceSecurity.CreateHardenedSecurity` grants full control to SYSTEM and
  Administrators, read/write to interactive local users, and explicitly denies network
  logons so the pipe is never reachable remotely. The connected Windows identity is
  verified while impersonating the client before any command runs, and the exchange is
  serialized one connection at a time. `FirewallServiceClient` is the unprivileged
  dashboard counterpart; it requires a LocalSystem-owned connected pipe before writing,
  then validates strict framing and request correlation on every reply.
- Framing is not authentication. Client-side pipe-owner verification authenticates the
  service endpoint; the ACL plus impersonated-identity check authenticate and authorise
  its caller. The policy file must still live in a service-owned ACL-protected directory.

## Safety requirements before enforcement

- Start in audit-only mode. No filter is installed until the user explicitly
  enables enforcement.
- Default to `ask`, then fail open while the prompt UI or service is unavailable.
- Never block loopback, DHCP, DNS to the configured resolver, or WinSight service
  IPC through a catch-all rule.
- Verify the executable identity again in the privileged service; dashboard input
  is untrusted.
- Apply and remove filters in WFP transactions, under a single provider/sublayer,
  so rollback and uninstall are deterministic.
- Keep emergency disable available through the authenticated IPC contract so a separate
  recovery client can invoke the same serialized authority without any direct WFP alias.
- Test on an isolated Windows VM before enabling persistent filters.

## Remaining Phase 2 increments

1. Done in code, pending native evidence. The named-pipe host, hardened ACL,
   impersonated-identity authentication, dispatcher, and service authority are hosted by a
   least-privilege Windows service worker (`WinSight.FirewallService`) that provisions an
   ACL-protected policy directory under ProgramData. The dashboard consumes structured pipe
   status through `FirewallServiceGateway`/`FirewallServiceAdapter`; an unreachable pipe is
   presented as unavailable, never as an unverified SCM installation state. The executable has
   opt-in, elevated `install`/`uninstall` verbs; the per-user setup never installs it.
2. Done in code, pending native evidence. WFP engine/session/provider/sublayer interop
   applies per-application IPv4 and IPv6 block filters after an explicit elevated
   enforcement transition. It must be exercised in an isolated Windows VM before merge;
   unit tests do not establish that a native filter was installed.
3. Prompt flow using the implemented durable policy store.
4. Done in code, pending native evidence. Enforcement opt-in, recovery command, and
   installer/uninstaller integration. The effective state is `Active` only after a
   successful apply; unavailable or degraded is never presented as installed or filtering.

No kernel callout driver is required for this user-mode outbound-control scope. Native
filtering remains blocked from production qualification until isolated-VM validation
proves the required WFP and connectivity scenarios.
