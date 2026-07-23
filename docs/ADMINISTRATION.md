# Administration guide

For the person who deploys WinSight on machines they are responsible for. If something is already
broken, go straight to [`RECOVERY.md`](RECOVERY.md).

## Deployment models

| Model | Install path | Elevation | Firewall service |
|---|---|---|---|
| Per-user (installer default) | `%LOCALAPPDATA%\Programs\WinSight` | none | **not available** |
| Machine-wide | `C:\Program Files\WinSight` | required | available |
| Portable ZIP | anywhere you extract it | none to scan | available only from a protected path |

The read-only scanners work in every model. The **outbound firewall service is deliberately not
installed by setup** — it registers a LocalSystem service and mutates the Windows Filtering Platform,
which is not something an installer should do without an explicit decision.

### Machine-wide install

Run setup elevated and choose the machine-wide option, or:

```powershell
winsight-v<version>-win-x64-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR="C:\Program Files\WinSight"
```

The install directory must be one **no unprivileged principal can write**. This is not advice: the
service verifies it and refuses to register otherwise. You can check a candidate path before
committing to it, without changing anything:

```powershell
& "C:\Program Files\WinSight\winsight-firewall-service.exe" install-path-trust-check "C:\Program Files\WinSight\winsight-firewall-service.exe"
```

`[FW_INSTALL_PATH_TRUSTED]` and exit 0 means the path is acceptable. Any other result names the
specific reason — see the table in [`RECOVERY.md`](RECOVERY.md).

## The firewall service

### Register and start

From an **elevated** console:

```powershell
& "C:\Program Files\WinSight\winsight-firewall-service.exe" install
sc start WinSightFirewall
```

It starts in **audit-only**. Nothing is filtered until someone arms it deliberately.

### Verify what it is actually doing

```powershell
& "C:\Program Files\WinSight\winsight-firewall-service.exe" enforce-status
& "C:\Program Files\WinSight\winsight-firewall-service.exe" wfp-status
& "C:\Program Files\WinSight\winsight-firewall-service.exe" wfp-block-status "C:\path\to\app.exe"
```

`enforce-status` reports the **persisted desired mode**, and says so — it deliberately does not claim
to know the live runtime state, because only the running service can prove that. `wfp-status` reports
the actual WFP objects. Trust `wfp-status` over any UI when the two disagree, and treat a disagreement
as a defect worth reporting.

### Arming enforcement

Enforcement can only be enabled through the **elevated dashboard**, over authenticated IPC. There is
no command-line path, and the direct mutation verbs are permanently disabled:

```
[FW_DIRECT_MUTATION_DISABLED]
```

That is the security property, not a missing feature. A command line that could arm the machine would
be a command line an attacker could use.

Arming order: Outbound firewall → Start analysis → Block an app → Enable enforcement → confirm.

### Emergency disable

The kill switch is in the dashboard: **Emergency disable**. It returns the machine to audit-only and
lifts every WinSight filter. It is designed to be safe to press when you are unsure.

Confirm afterwards, and do not take the dialog's word for it:

```powershell
& "C:\Program Files\WinSight\winsight-firewall-service.exe" wfp-status
```

Expect `provider: absent, sublayer: absent, permit-filter: absent`.

### Remove the service

```powershell
sc stop WinSightFirewall
& "C:\Program Files\WinSight\winsight-firewall-service.exe" uninstall
sc query WinSightFirewall
```

`sc query` must end with error **1060** (service does not exist). Uninstalling the *application*
does not remove the service — the service is a separate, deliberate registration.

## Where state lives

| Path | Contents |
|---|---|
| `%ProgramData%\WinSight` | Policy store, ACL-protected, machine scope |
| `%LOCALAPPDATA%\WinSight` | Per-user dashboard settings and alert journal |
| Windows service `WinSightFirewall` | The privileged component |

The policy store's trust is re-checked before every read and write. A store WinSight cannot trust
recovers to audit-only with a diagnostic rather than being partially honoured.

## Operating notes

- **Enforcement survives reboots**, because the desired mode is persisted and the service is
  boot-registered. Verify with `wfp-status` after a reboot rather than assuming.
- **No telemetry.** The only outbound connection is an explicit, user-initiated VirusTotal hash
  lookup, rate-limited per user.
- **Scanners are read-only.** `winsight.exe` exits non-zero when anything notable is found, which
  makes it usable from a scheduled task or monitoring hook.
- **Unsigned binaries.** Until the project holds a code-signing certificate, Windows will warn on
  first run. Verify what you downloaded using [`RELEASE.md`](RELEASE.md) before granting it
  Administrator rights.

## Validating a deployment yourself

The scripts that qualify a build ship inside the package. On an **isolated VM**, never a production
machine:

```powershell
& "C:\Program Files\WinSight\Test-WfpValidation.ps1" -ContractSelfTest
& "C:\Program Files\WinSight\Test-TrustBoundary.ps1"
& "C:\Program Files\WinSight\Test-IpcBoundary.ps1"
```

Full procedure and expected counts: [`validation/VM_QUALIFICATION_KIT.md`](validation/VM_QUALIFICATION_KIT.md).
