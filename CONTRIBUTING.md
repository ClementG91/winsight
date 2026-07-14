# Contributing to WinSight

Thanks for your interest! WinSight is a free, open-source security suite for Windows.
Contributions of code, tests, docs, and bug reports are all welcome.

## Ground rules

- **Read-only by default.** WinSight tools observe and report; they must never
  silently modify or delete user data. Any future blocking/quarantine feature must be
  explicit and opt-in.
- **No telemetry.** The suite is local-only. Network calls (e.g. reputation lookups)
  must be opt-in and user-keyed.
- **Transparency.** This is a security tool — code must be auditable. Prefer clear,
  documented implementations over clever ones.

## Project layout

```
src/        tool libraries, shared application layer, CLI, WPF dashboard and MCP server
tests/      xUnit unit, integration, frontend and localization tests
installer/  multilingual Inno Setup definition
scripts/    dependency audit, packaging and installer validation
docs/       architecture, installation, detection and Phase 2 safety contracts
```

Tools are pure data producers; presentation lives in the `winsight` CLI via
`Reporting`. See `docs/ARCHITECTURE.md`.

## Building and testing

The code targets **.NET 10 LTS (`net10.0-windows10.0.19041.0`)** and must be
built on **Windows 10 22H2 or newer**.

```powershell
dotnet restore winsight.sln
dotnet build winsight.sln -c Release --no-restore
dotnet test winsight.sln -c Release --no-build
```

The full release candidate can be reproduced with:

```powershell
./scripts/Build-Release.ps1 -Version 0.7.0
./scripts/Test-Installer.ps1 `
  -InstallerPath out/release/winsight-v0.7.0-win-x64-setup.exe `
  -Version 0.7.0 -Architecture x64
```

CI builds/tests on Windows, audits dependencies, constructs x64 and Arm64 packages,
and executes each installer plus the trilingual WPF smoke test on a native runner.
The same lifecycle negotiates with the installed MCP server and verifies that every
published MCP tool remains read-only and non-destructive.
**All checks must be green** before a PR is merged or a release is published.

## Coding standards

- Follow `.editorconfig` and the existing style; `TreatWarningsAsErrors` is on.
- Add tests: pure logic as unit tests, real-system behavior as integration tests.
- Native interop stays behind an interface with a managed fallback where practical.
- Architecture-specific code needs native x64 and Arm64 coverage or a documented,
  fail-closed reason why it cannot run on one of them.
- Installer changes must preserve least privilege, clean uninstall and the separation
  between read-only Phase 1 functionality and disabled Phase 2 enforcement.
- MCP tools must remain local-stdio, bounded and read-only. New evidence fields need
  an explicit privacy review; never expose a mutation tool merely because a scanner
  can identify a Windows object.
- Keep the Phase-1 lexicon: recognition / status / signal — never security theater.

## Commit & PR process

1. Branch from `main`.
2. Use clear, conventional commit messages (`feat(scope): …`, `fix(scope): …`).
3. Update `README.md` and `CHANGELOG.md` when behavior changes.
4. Open a PR using the template; ensure CI is green.
5. A maintainer reviews and merges.

## Reporting bugs / requesting features

Use the issue templates. For **security vulnerabilities**, do NOT open a public
issue — see [SECURITY.md](SECURITY.md).

By contributing, you agree that your contributions are licensed under the project's
[GPL-3.0-or-later](LICENSE) license.
