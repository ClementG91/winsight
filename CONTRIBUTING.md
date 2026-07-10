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
src/    tool libraries (Core, Persistence, AvMonitor, NetMonitor, Reporting) + the winsight CLI
tests/  xUnit tests (pure unit tests + Windows integration tests)
```

Tools are pure data producers; presentation lives in the `winsight` CLI via
`Reporting`. See `docs/ARCHITECTURE.md`.

## Building and testing

The code targets **.NET 8 (`net8.0-windows`)** and must be built on **Windows**.

```powershell
dotnet build -c Release
dotnet test  -c Release
```

CI (GitHub Actions, `windows-latest`) auto-discovers and builds/tests every project on
every push and PR. **All checks must be green** before a PR is merged.

## Coding standards

- Follow `.editorconfig` and the existing style; `TreatWarningsAsErrors` is on.
- Add tests: pure logic as unit tests, real-system behavior as integration tests.
- Native interop stays behind an interface with a managed fallback where practical.
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
