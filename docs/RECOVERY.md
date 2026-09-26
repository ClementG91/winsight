# Recovery runbook

For when something is wrong now. Each section states the symptom, what is actually true underneath,
and the shortest safe way out.

Every command below is read-only unless it says otherwise. Run them from an **elevated** console in
the install directory.

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
