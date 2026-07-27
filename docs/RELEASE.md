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

`release.yml` then builds both architectures — x64 on the pinned `windows-2025` image, Arm64 on the
**native** `windows-11-arm` runner — runs the full installer lifecycle on each, signs, checksums,
attests and publishes.

Runner images are pinned rather than following `windows-latest`. The label resolves to `windows-2025`
today, so the pin changes nothing now — that is the point. It moves on GitHub's schedule, and this
workflow produces the binaries someone downloads and runs; a release built on an image no CI leg ever
exercised is an unreviewed change to the artifact arriving without a commit. `ci.yml` pins the same
image and covers `windows-2022` and native `windows-11-arm` beside it. Moving to a newer image is a
deliberate one-line commit.

**Pinning the label is not the same as pinning the image**, and this document should not pretend
otherwise. GitHub migrated both `windows-latest` and `windows-2025` to a Visual Studio 2026 image in
June 2026, and hosted images are re-cut weekly regardless — so `runs-on: windows-2025` names a moving
target, just a slowly moving one that only moves when GitHub says so rather than continuously. There
is no immutable hosted-image label to reach for, so the mitigation is evidence rather than a stronger
pin: each build job records `ImageOS` and `ImageVersion` in the workflow run summary, which turns
"built on windows-2025" into an exact image a future reader can pin a behavioural difference to.

## Authenticode signing

Signing runs inside `Build-Release.ps1`, deliberately **before** archives are compressed and
**before** any checksum is computed. Signing afterwards would leave every published hash describing
bytes that no longer exist.

The unsigned public v0.10.3 release pipeline successfully published x64 and Arm64 assets with GitHub
build-provenance and SBOM attestations; its x64 artifact was independently observed as `NotSigned`.
The signed Authenticode production chain has never been exercised end to end, so signing is not a
closed release gate. The repository variable `REQUIRE_SIGNED_RELEASE=true` was set and re-read at
2026-07-26T14:55:05Z, so the release workflow now fails closed when signing is unavailable. Neither
`WINSIGHT_SIGNING_CERT_BASE64` nor `WINSIGHT_SIGNING_CERT_PASSWORD` is configured. A signed release
remains blocked until a real certificate is configured and verified.

The user explicitly authorized a public unsigned v0.10.4 release under a one-release waiver dated
2026-07-26. `REQUIRE_SIGNED_RELEASE` will be intentionally disabled for that waived release so the
known absence of a certificate does not stop it. The resulting artifacts are expected to be unsigned
and to trigger the normal Windows unknown-publisher warning. This exception does not exercise or
establish the signed Authenticode production chain, and it does not establish product readiness.

#### Second unsigned waiver — v0.10.5, dated 2026-07-27

A second unsigned public release was explicitly authorized on 2026-07-27, on the same terms and with
the same limits. Recording it honestly matters more than the tidiness of having said "one release
only" the first time: this is now a **pattern**, not an exception, and the document should say so
rather than let a reader infer a discipline that is not being kept.

Why it was granted, so the trade is auditable rather than assumed:

- v0.10.5 carries three user-affecting corrections — a detection notification that could not be
  clicked open, a Controlled Folder Access posture that read "unavailable" on machines running a
  non-Microsoft antivirus, and the Security Center inventory that stops the ransomware-shield verdict
  from leaving a false impression on exactly those machines.
- **v0.10.4 already shipped unsigned.** An unsigned v0.10.5 is therefore not a regression in posture;
  it is the same posture carrying fixes. Withholding the fixes would have been the larger harm.
- An application to the SignPath Foundation free code-signing programme for open-source projects is
  pending. It had not been answered when this release was cut, and its outcome is not certain.

`REQUIRE_SIGNED_RELEASE` is set back to `true` immediately after publication. It is a gate that fails
closed by default, opened deliberately and briefly, and closed again — not a setting left off.

**This waiver expires with v0.10.5.** A third unsigned release should not be waved through on the
strength of the first two; if signing is still unavailable by then, the honest response is to fix the
signing path rather than to keep writing paragraphs like this one.

### Values required to enable the signing path

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

It is never silent. The normal repository setting `REQUIRE_SIGNED_RELEASE=true` makes a missing
certificate a hard failure, so the release workflow cannot quietly lose its signature. It has been
intentionally disabled only for the two explicitly waived unsigned releases described above — v0.10.4
and v0.10.5 — and set back to `true` immediately after each was published.

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
- [ ] Signing verified with a real certificate, or an explicit unsigned-release waiver recorded
- [ ] Downloaded assets verified with the four checks above
