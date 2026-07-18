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
  operation with a stable code and redacted message.
- ACL evaluation is deterministic and follows DACL order: an earlier applicable Deny ACE
  removes matching dangerous rights before a later Allow is considered, while a later deny
  cannot revoke rights already allowed. Exact SID and well-known broad-group applicability
  are resolved directly; arbitrary group expansion is injectable for tests, and unknown
  membership is never used to turn a dangerous Allow into trust.
- Inspection produces stable volume/file identities from no-follow handles. The installer
  revalidates those identities immediately before SCM use and after registration; a
  mismatch rolls the new registration back. Storage guards similarly bind each load/save
  to pre-use metadata and post-open/pre-replace identity checks. These checks narrow but
  do not replace the outstanding adversarial TOCTOU validation in an isolated VM.
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

The following evidence remains blocked pending explicit human execution in an isolated
Windows VM: real SCM lifecycle and no-call-on-denial observation; owner/DACL and nested
reparse/TOCTOU cases; standard/elevated/SYSTEM multi-user pipe tokens; WFP enumeration,
startup recovery and rollback; and IPv4/IPv6/DNS/DHCP/loopback connectivity.

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
