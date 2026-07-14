# Installing WinSight

WinSight is distributed as a per-user installer and as a portable ZIP. Both are
self-contained: the .NET runtime is included and no account, service or telemetry
component is installed.

## Choose the correct download

| Windows device | Installer | Portable archive |
|---|---|---|
| Intel or AMD 64-bit PC | `winsight-vX.Y.Z-win-x64-setup.exe` | `winsight-vX.Y.Z-win-x64.zip` |
| Windows on Arm PC | `winsight-vX.Y.Z-win-arm64-setup.exe` | `winsight-vX.Y.Z-win-arm64.zip` |

The x64 installer deliberately refuses to install on Arm when the native Arm64
package is available. 32-bit x86 Windows is not supported.

## Supported Windows baseline

- Windows 11 x64 or Arm64.
- Windows 10 22H2 x64 or Arm64, only while that Windows edition remains supported
  by Microsoft (including an applicable ESU program).
- Minimum installer build: Windows 10 22H2, build 19045.

WinSight may run on newer Windows Server editions, but the desktop dashboard and
consumer registry surfaces are not formally supported there. Older Windows builds
and 32-bit Windows are intentionally rejected: a security product should not claim
production support for an operating system outside its vendor security lifecycle.

## Installer

1. Download the installer matching the processor architecture.
2. Verify its checksum using the adjacent `.sha256` file (see below).
3. Run the installer and select English, French or Spanish.
4. Launch **WinSight** from the Start menu.

The default installation is per-user under `%LOCALAPPDATA%\Programs\WinSight` and
does not request elevation. The installer adds Start-menu shortcuts, offers an
optional desktop shortcut, and registers a normal Windows uninstaller. It does not
change `PATH`, install a driver or enable firewall enforcement.

The installed `winsight.exe mcp` mode is an on-demand local MCP child process for AI
clients. The installer does not enable it, add it to startup, create a service or
open a network port. See [`MCP.md`](MCP.md) before connecting an AI client.

## Optional VirusTotal reputation

VirusTotal is disabled by default. Each user who wants reputation enrichment must
create their **own** VirusTotal Community account/API key. The project maintainer must
never embed, publish or share a single project key: that would expose a credential,
mix users' quota and remove meaningful consent for sending hashes to a third party.

For an interactive installation, open **Settings** in the WinSight header, paste the
key and choose **Save securely**. The key is encrypted at rest with Windows DPAPI for
the current account, is available immediately, and is never written to reports or
exports. Choose **Disable** in the same dialog to remove the encrypted key.

For a standard Community key, WinSight coordinates dashboard and CLI requests with a
persistent per-user guard: no more than 4 lookups in any rolling 60-second window,
500 in a UTC day, or 15,500 in a UTC month. It does not retry a rejected or HTTP 429
request. Activity made through the VirusTotal website or another application is not
visible to this local counter, so the provider's remaining quota is always final.
Community access is for personal/non-commercial use only; a business, commercial or
government workflow requires an appropriate VirusTotal Premium agreement. See the
official [Public API rules](https://docs.virustotal.com/reference/getting-started)
and [quota reset behaviour](https://docs.virustotal.com/docs/consumption-quotas-handled).

Managed deployments and portable CLI automation can instead set the user environment
variable below. It takes precedence over the dashboard's encrypted setting:

```powershell
# Run as the normal Windows user; no Administrator shell is required.
[Environment]::SetEnvironmentVariable("WINSIGHT_VT_KEY", "PASTE-YOUR-OWN-KEY", "User")
```

Close and reopen WinSight after setting an environment variable. To remove it again:

```powershell
[Environment]::SetEnvironmentVariable("WINSIGHT_VT_KEY", $null, "User")
```

Never put the key in a bug report, exported scan, repository file or screenshot.
WinSight submits only SHA-256 lookups for a bounded number of flagged, existing
files. A blank VirusTotal result is expected when the key is absent, the target file
is missing (there is nothing to hash), the lookup is disabled in MCP mode, the hash
is unknown to VirusTotal, or the user's quota/network is unavailable.

## Portable archive

Extract the ZIP to a directory you control, then run `winsight-dashboard.exe`.
Administrators and automation users can run `winsight.exe --help`. Keep the files
inside the archive together, including the `_manifest` SBOM directory.

## Optional outbound-firewall service (audit-only)

WinSight ships `winsight-firewall-service.exe`, the Phase 2 outbound-firewall service.
It is **opt-in and not installed by the per-user setup**, because registering a Windows
service requires Administrator rights. The service is **audit-only**: it records
per-application policies but installs no Windows Filtering Platform filter, so your
network connectivity is never affected.

From an **elevated** (Administrator) console, in the install or extracted directory:

```powershell
# Register the demand-start, LocalSystem service (audit-only, no filter installed)
.\winsight-firewall-service.exe install

# Check registration, or remove it
.\winsight-firewall-service.exe status
.\winsight-firewall-service.exe uninstall

# Read-only WFP interop probe: opens the Windows Filtering Platform engine and counts
# existing filters, then closes. It never adds or changes a filter, so connectivity is
# untouched. Useful to confirm WFP access before any enforcement work.
.\winsight-firewall-service.exe wfp-selftest

# Create/remove the WinSight WFP provider and sublayer. These are namespace containers
# only: they filter no traffic and cannot block a connection. They are non-persistent
# (a reboot removes them) and exist so future audit-only filters have an owner.
.\winsight-firewall-service.exe wfp-provision
.\winsight-firewall-service.exe wfp-status
.\winsight-firewall-service.exe wfp-deprovision

# Add/remove a non-blocking PERMIT filter in the WinSight sublayer. A PERMIT authorizes
# outbound connects (already the default), so it blocks nothing; it proves the filter
# interop. Requires wfp-provision first.
.\winsight-firewall-service.exe wfp-filter-add
.\winsight-firewall-service.exe wfp-filter-remove

# Block ONE application's outbound connections, matched by executable path. Only that
# binary is affected; every other app keeps working. Requires wfp-provision first.
# Test it safely with a copy of a harmless tool, e.g.:
#   Copy-Item C:\Windows\System32\ping.exe C:\pingtest.exe
#   .\winsight-firewall-service.exe wfp-block-add C:\pingtest.exe
#   C:\pingtest.exe 8.8.8.8      # fails (blocked), while normal ping still works
#   .\winsight-firewall-service.exe wfp-block-remove
.\winsight-firewall-service.exe wfp-block-add "C:\full\path\to\app.exe"
.\winsight-firewall-service.exe wfp-block-remove
```

Once registered, the dashboard's **Outbound Firewall** view changes from "service not
installed" to the live audit-only status. Enforcement (actually blocking traffic) is a
separate, later, opt-in step and is not part of this release.

## Integrity and provenance

Verify a download in PowerShell:

```powershell
$artifact = "winsight-v0.8.1-win-x64-setup.exe"
$expected = (Get-Content "$artifact.sha256").Split()[0]
$actual = (Get-FileHash $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "WinSight checksum mismatch" }
```

GitHub releases also carry a build-provenance attestation. The project currently
does **not** have a public Authenticode code-signing certificate, so Windows may show
a SmartScreen unknown-publisher warning. A valid checksum and GitHub attestation
protect integrity and provenance, but they are not a substitute for Authenticode.

## Managed and silent installation

```powershell
# Per-user, silent, no automatic launch
./winsight-v0.8.1-win-x64-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART

# Explicit language: english, french, or spanish
./winsight-v0.8.1-win-x64-setup.exe /LANG=french
```

Use the architecture-specific artifact in deployment tooling. Do not redistribute
an x64 package as a native Arm64 package.
