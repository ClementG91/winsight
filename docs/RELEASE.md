# Release process

How a WinSight release is cut, signed, attested and verified — and how someone who did not build it
can check that what they downloaded is what this repository produced.

## What a release contains

Per architecture (`x64`, `arm64`):

| Asset | Purpose |
|---|---|
| `winsight-v<version>-win-<arch>.zip` | portable package: binaries, docs, branding, validation scripts |
| `winsight-v<version>-win-<arch>-setup.exe` | Inno Setup installer |
| `winsight-v<version>-win-<arch>.spdx.json` | SPDX SBOM |
| `*.sha256` | SHA-256 for each of the above |

Plus GitHub **build provenance** and **SBOM attestations**, signed by GitHub's OIDC identity.

## Cutting a release

1. Bump `<Version>` in `Directory.Build.props`. The workflow refuses to build if the tag and the
   project version disagree, so a mistyped tag stops the release rather than shipping a mislabelled
   artifact.
2. Land it through a pull request with green CI.
3. Tag and push:

```bash
git tag v0.11.0 && git push origin v0.11.0
```

`release.yml` then builds both architectures — x64 on `windows-latest`, Arm64 on the **native**
`windows-11-arm` runner — runs the full installer lifecycle on each, signs, checksums, attests and
publishes.

## Authenticode signing

Signing runs inside `Build-Release.ps1`, deliberately **before** archives are compressed and
**before** any checksum is computed. Signing afterwards would leave every published hash describing
bytes that no longer exist.

### What the maintainer must supply

A code-signing certificate cannot live in a public repository. Provide it as repository secrets:

| Secret | Value |
|---|---|
| `WINSIGHT_SIGNING_CERT_BASE64` | base64 of a PFX containing the code-signing key |
| `WINSIGHT_SIGNING_CERT_PASSWORD` | that PFX's password |

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('winsight-signing.pfx')) | Set-Clipboard
```

An OV or EV certificate from a CA in the Windows trusted root program is required for Windows to
accept the signature. A self-signed certificate will sign successfully and then **fail verification**
— see below.

### Behaviour when no certificate is configured

The build still succeeds, and says so loudly:

```
[SIGNING] SKIPPED - no certificate configured.
[SIGNING] 12 file(s) will ship UNSIGNED. Windows will warn users on first run.
```

It is never silent. To make a missing certificate a hard failure — so a release cannot quietly lose
its signature — set the repository variable `REQUIRE_SIGNED_RELEASE` to `true`.

### Why signing is verified, not assumed

`Sign-Artifacts.ps1` runs `signtool verify /pa /all` on every file after signing it. A zero exit from
`signtool sign` only says the tool ran; it does not say the file now carries a chain-valid signature.

This is not theoretical. Signing a binary with a self-signed certificate on a machine where that
certificate is not a trusted root produces:

```
[SIGNING] tool: ...\signtool.exe
signtool signed ...\probe.exe but verification failed (exit 1).
```

The signature is genuinely applied and genuinely timestamped — `Get-AuthenticodeSignature` reports
the signer and a timestamp — and it is still worthless, because the chain does not validate. Trusting
the `sign` exit code alone would have shipped that.

## Verifying a release you downloaded

**1. Checksum.**

```powershell
Get-FileHash winsight-v0.11.0-win-x64.zip -Algorithm SHA256
Get-Content winsight-v0.11.0-win-x64.zip.sha256
```

**2. Provenance** — proves GitHub Actions built this exact file from this repository:

```bash
gh attestation verify winsight-v0.11.0-win-x64.zip --repo ClementG91/winsight
```

**3. Authenticode**, when the release is signed:

```powershell
Get-AuthenticodeSignature .\winsight-dashboard.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

`Status` must be `Valid`. Anything else means do not run it with Administrator rights.

**4. Architecture** — the PE header, not the file name:

```powershell
./scripts/Test-PeArchitecture.ps1 -Path .\winsight.exe -Architecture x64
```

## Substitution resistance

An attacker replacing a release asset must defeat all of:

- the SHA-256 published beside it,
- GitHub's build-provenance attestation, bound to the workflow, repository and commit,
- the SBOM attestation,
- Authenticode, when a certificate is configured.

The checksums are generated in the build job and **re-verified in a separate `publish` job** after
artifacts move between jobs, so corruption or substitution in transit fails the release rather than
being published.

What this does **not** defend against: a compromise of the GitHub account or of the signing
certificate itself. Provenance proves *which workflow built it*, not that the workflow was
trustworthy at the time.

## Release checklist

- [ ] `Directory.Build.props` version bumped and merged
- [ ] `CHANGELOG.md` describes the release
- [ ] CI green on `main`
- [ ] Validation records in `docs/validation/` still bind to reachable commits
- [ ] `production_ready` statement in `docs/PRODUCTION_READINESS.md` reflects reality
- [ ] Tag pushed; `release.yml` green on both architectures
- [ ] Signing status confirmed in the build log (signed, or knowingly unsigned)
- [ ] Downloaded assets verified with the four checks above
