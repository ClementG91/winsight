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

## Portable archive

Extract the ZIP to a directory you control, then run `winsight-dashboard.exe`.
Administrators and automation users can run `winsight.exe --help`. Keep the files
inside the archive together, including the `_manifest` SBOM directory.

## Integrity and provenance

Verify a download in PowerShell:

```powershell
$artifact = "winsight-v0.7.1-win-x64-setup.exe"
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
./winsight-v0.7.1-win-x64-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART

# Explicit language: english, french, or spanish
./winsight-v0.7.1-win-x64-setup.exe /LANG=french
```

Use the architecture-specific artifact in deployment tooling. Do not redistribute
an x64 package as a native Arm64 package.
