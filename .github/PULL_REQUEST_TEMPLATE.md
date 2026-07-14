<!-- Thanks for contributing to WinSight! -->

## What & why

<!-- What does this change do, and why? Link any related issue: Closes #123 -->

## Type

- [ ] Feature
- [ ] Bug fix
- [ ] Refactor / maintenance
- [ ] Docs / CI

## Checklist

- [ ] Builds and tests pass on Windows (`dotnet build -c Release`, `dotnet test -c Release`), CI is green
- [ ] Added/updated tests (unit for pure logic, integration for real-system behavior)
- [ ] Updated `README.md` and `CHANGELOG.md` if behavior changed
- [ ] Read-only / local-only principles respected (no silent modification, no telemetry)
- [ ] Native interop (if any) sits behind an interface with a fallback where practical
