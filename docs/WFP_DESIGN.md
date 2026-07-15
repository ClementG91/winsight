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
3. A dedicated Windows service is the only process allowed to mutate WFP. It
   implements `IOutboundFirewallEngine` over authenticated local IPC.
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
  is lazy and occurs only after a fresh trusted load. CLI mutation verbs are disabled
  because the current protocol has no privileged transition commands to route safely.
  The central mode gate prevents adding/applying filters in AuditOnly. The only mutation is
  idempotent WinSight-owned cleanup during emergency/disable, ordered before AuditOnly is
  persisted.
- Enforcement-side policy changes compensate a persistence failure by restoring the prior
  owned filter state. Enable and startup track successfully applied filters; partial failure
  removes them in reverse order and persists AuditOnly. Failure of compensation is distinct
  from the initiating transition failure so operators cannot mistake divergence for a safe
  rollback.
- External failures use stable protocol/path codes and fixed messages. They do not expose
  attacker-controlled paths, ACLs, SIDs, policy JSON, or native exception text.
- IPC, CLI output and hosted-service logs are independent diagnostic trust boundaries.
  Hosted services never attach caught exception objects to log records; fixed allowlisted
  `FW_*` codes preserve observability without allowing providers to serialize nested
  native or attacker-controlled text.
- Security codes are locale-invariant. This service surface emits codes rather than new
  ad-hoc English presentation; user-facing WinSight presentation continues to use the
  existing EN/FR/ES localization layer. The VM protocol must inspect affected presentation
  in all three locales without changing the underlying codes.

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
  payload shape, canonical paths, enums and response invariants. Policy listing is
  explicitly paged at no more than 128 entries per frame.
- `AuditOnlyFirewallEngine` remains a non-mutating test and fallback implementation. The
  production service authority does not freeze an engine choice at startup: it constructs
  the native backend lazily only after a fresh trusted load requires enforcement or owned
  cleanup.
- `FirewallRequestDispatcher` turns a validated request into an effect against the
  store and engine. An unauthenticated caller only ever receives `Unauthorized`; store
  or engine faults collapse to `InternalFailure` with no exception text on the wire;
  and it never promotes the persisted mode to enforcement. `EmergencyDisable` always
  returns the machine to audit-only, even from a corrupt store.
- `FirewallConnectionHandler` serves one authenticated request/response exchange over
  any duplex stream, so the logic is tested without a pipe or elevation.
- `NamedPipeFirewallServer` hosts the endpoint over a hardened local pipe.
  `FirewallServiceSecurity.CreateHardenedSecurity` grants full control to SYSTEM and
  Administrators, read/write to interactive local users, and explicitly denies network
  logons so the pipe is never reachable remotely. The connected Windows identity is
  verified while impersonating the client before any command runs, and the exchange is
  serialized one connection at a time. `FirewallServiceClient` is the unprivileged
  dashboard counterpart; it validates every reply through the same strict codec.
- Framing is not authentication. The ACL plus impersonated-identity check are the
  authentication; the policy file must still live in a service-owned ACL-protected
  directory.

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
- Keep emergency disable and complete filter cleanup commands available without
  requiring the dashboard.
- Test on an isolated Windows VM before enabling persistent filters.

## Remaining Phase 2 increments

1. Done. The named-pipe host, hardened ACL, impersonated-identity authentication,
   dispatcher and audit-only engine are implemented and tested, hosted by a
   least-privilege Windows service worker (`WinSight.FirewallService`) that provisions an
   ACL-protected policy directory under ProgramData, surfaced read-only in the dashboard
   through `FirewallServiceGateway`/`FirewallServiceAdapter` (an "Outbound Firewall"
   navigation entry that degrades to "service not installed"), and shipped as
   `winsight-firewall-service.exe` with opt-in, elevated `install`/`uninstall` verbs that
   register a demand-start, LocalSystem, audit-only service through the SCM. The per-user
   setup never installs it.
2. WFP engine/session/provider/sublayer interop and audit-only filters. This is the
   first increment that touches real filters and must be developed and validated on an
   isolated Windows VM before it ships.
3. Prompt flow using the implemented durable policy store.
4. Enforcement opt-in, recovery command, installer/uninstaller integration.

No kernel callout driver is required for this user-mode outbound-control scope. No
increment installs a live WFP filter until it has been safety-tested in isolation, so
the shipped build stays read-only and audit-only.
