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
- Framing is not authentication. The future named-pipe host must apply a restrictive
  ACL and verify the impersonated Windows identity before it decodes or executes a
  frame. The policy file must live in a service-owned ACL-protected directory.

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

1. Least-privilege service host + named-pipe ACL and Windows-identity authentication
   using the implemented framing protocol.
2. WFP engine/session/provider/sublayer interop and audit-only filters.
3. Prompt flow using the implemented durable policy store.
4. Enforcement opt-in, recovery command, installer/uninstaller integration.

No kernel callout driver is required for this user-mode outbound-control scope.
