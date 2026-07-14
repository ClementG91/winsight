# Phase 2, outbound firewall design

Status: contracts, fail-open policy storage and strict IPC framing implemented; no
service is installed and WFP mutation is not enabled.

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
- `AuditOnlyFirewallEngine` is the default engine and never mutates WFP. It reports
  `IsSupported = false`, so the service can never present enforcement as active. This
  keeps the machine's connectivity untouched while enforcement is still being built.
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
