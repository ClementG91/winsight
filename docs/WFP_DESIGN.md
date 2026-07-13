# Phase 2 — outbound firewall design

Status: contracts and safety boundary implemented; WFP mutation is not enabled yet.

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

The shared `AppFirewallPolicy` and `OutboundPolicyEvaluator` contracts are already
implemented and unit-tested. They intentionally use executable paths rather than
process ids or display names, which are transient or ambiguous.

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

1. Service + authenticated named-pipe protocol.
2. WFP engine/session/provider/sublayer interop and audit-only filters.
3. Prompt flow and durable policy store.
4. Enforcement opt-in, recovery command, installer/uninstaller integration.

No kernel callout driver is required for this user-mode outbound-control scope.
