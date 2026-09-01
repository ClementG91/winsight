# Release process

How a WinSight release is cut, signed, attested and verified - and how someone who did not build it
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
git tag vX.Y.Z && git push origin vX.Y.Z
```

`release.yml` then builds both architectures - x64 on the pinned `windows-2025` image, Arm64 on the
**native** `windows-11-vs2026-arm` runner - runs the full installer lifecycle on each, signs,
checksums, attests and publishes.

Runner images are pinned rather than following `windows-latest`. The label resolves to `windows-2025`
today, so the pin changes nothing now - that is the point. It moves on GitHub's schedule, and this
workflow produces the binaries someone downloads and runs; a release built on an image no CI leg ever
exercised is an unreviewed change to the artifact arriving without a commit. `ci.yml` pins the same
image and covers `windows-2022` and native `windows-11-vs2026-arm` beside it. Moving to a newer image
is a deliberate one-line commit.

**Pinning the label is not the same as pinning the image**, and this document should not pretend
otherwise. GitHub migrated both `windows-latest` and `windows-2025` to a Visual Studio 2026 image in
June 2026, and hosted images are re-cut weekly regardless - so `runs-on: windows-2025` names a moving
target, just a slowly moving one that only moves when GitHub says so rather than continuously. There
is no immutable hosted-image label to reach for, so the mitigation is evidence rather than a stronger
pin: each build job records `ImageOS` and `ImageVersion` in the workflow run summary, which turns
"built on windows-2025" into an exact image a future reader can pin a behavioural difference to.

## Authenticode signing

Signing runs inside `Build-Release.ps1`, deliberately **before** archives are compressed and
**before** any checksum is computed. Signing afterwards would leave every published hash describing
bytes that no longer exist.

Every public release to date, through v0.11.6, is unsigned. The signed
Authenticode production chain has never been exercised end to end. SignPath Foundation declined the
free-program application on 2026-07-29 because the project does not yet have sufficient public
adoption and independent visibility.

On 2026-07-30 the project replaced the per-release waiver model with an explicit unsigned
distribution policy. The repository variable is `REQUIRE_SIGNED_RELEASE=false`; neither signing
secret is configured. The workflow accepts only the literal policy values `true` or `false`, fails if
the variable is absent or malformed, passes `-DisableSignature` so residual credentials cannot sign
opportunistically, and writes the unsigned posture to the run summary. This permits release
publication but does not establish a Windows publisher identity or product readiness.

The user explicitly authorized a public unsigned v0.10.4 release under a one-release waiver dated
2026-07-26. `REQUIRE_SIGNED_RELEASE` was intentionally disabled for that waived release so the
known absence of a certificate did not stop it. The resulting artifacts were unsigned and trigger
the normal Windows unknown-publisher warning. This exception does not exercise or
establish the signed Authenticode production chain, and it does not establish product readiness.

#### Second unsigned waiver - v0.10.5, dated 2026-07-27

A second unsigned public release was explicitly authorized on 2026-07-27, on the same terms and with
the same limits. Recording it honestly matters more than the tidiness of having said "one release
only" the first time: this is now a **pattern**, not an exception, and the document should say so
rather than let a reader infer a discipline that is not being kept.

Why it was granted, so the trade is auditable rather than assumed:

- v0.10.5 carries three user-affecting corrections - a detection notification that could not be
  clicked open, a Controlled Folder Access posture that read "unavailable" on machines running a
  non-Microsoft antivirus, and the Security Center inventory that stops the ransomware-shield verdict
  from leaving a false impression on exactly those machines.
- **v0.10.4 already shipped unsigned.** An unsigned v0.10.5 is therefore not a regression in posture;
  it is the same posture carrying fixes. Withholding the fixes would have been the larger harm.
- The SignPath Foundation application had not been answered when this release was cut. It was later
  declined on visibility/adoption grounds.

This historical waiver expired with v0.10.5. It is superseded by the explicit unsigned policy dated
2026-07-30 above; future releases must not describe the old waiver as the current control.

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
- see below.

### Behaviour when no certificate is configured

The build still succeeds, and says so loudly:

```
[SIGNING] SKIPPED - no certificate configured.
[SIGNING] 3 file(s) will ship UNSIGNED. Windows will warn users on first run.
```

It is never silent. `REQUIRE_SIGNED_RELEASE=false` is the current explicit policy, and the workflow
adds that fact to its summary. An absent or malformed policy value is a hard failure. Setting the
variable to `true` reactivates the certificate requirement and makes a missing or invalid signature a
hard failure.

### Why signing is verified, not assumed

`Sign-Artifacts.ps1` runs `signtool verify /pa /all` on every file after signing it. A zero exit from
`signtool sign` only says the tool ran; it does not say the file now carries a chain-valid signature.

This is not theoretical. Signing a binary with a self-signed certificate on a machine where that
certificate is not a trusted root produces:

```
[SIGNING] tool: ...\signtool.exe
signtool signed ...\probe.exe but verification failed (exit 1).
```

The signature is genuinely applied and genuinely timestamped - `Get-AuthenticodeSignature` reports
the signer and a timestamp - and it is still worthless, because the chain does not validate. Trusting
the `sign` exit code alone would have shipped that.

## Verifying a release you downloaded

**1. Checksum.**

```powershell
Get-FileHash winsight-vX.Y.Z-win-x64.zip -Algorithm SHA256
Get-Content winsight-vX.Y.Z-win-x64.zip.sha256
```

**2. Provenance** - proves GitHub Actions built this exact file from this repository:

```bash
gh attestation verify winsight-vX.Y.Z-win-x64.zip --repo ClementG91/winsight
```

**3. Authenticode**, when the release is signed:

```powershell
Get-AuthenticodeSignature .\winsight-dashboard.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

`Status` must be `Valid`. Anything else means do not run it with Administrator rights.

**4. Architecture** - the PE header, not the file name:

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

The v0.12.0 native-x64 candidate `dbaded1` has a candidate-bound VM record covering installer,
WFP/SCM, trust, local/Network IPC, ETW/session recovery and final cleanup. Exact CI `33416259797`
and CodeQL `33416257089` passed, including native Arm64 build/test/package/installer. The earlier
dashboard candidate `3912d67` separately passed Windows 11 VM layout, posture and EN/FR/ES smoke
checks. An independent EN/FR/ES presentation review
remains recommended; the French flow has project-owner review and all languages have automated
resource/layout and smoke coverage. Privileged Arm64 and x64-on-Arm64 identity remain hardware-bound
gates for Arm64 production claims. The Authenticode result must match the explicit repository
policy; under the current unsigned policy it must be `NotSigned` and visibly reported. Historical
validation records remain bound to their original commits.

## Release checklist

- [ ] `Directory.Build.props` version bumped and merged
- [ ] `CHANGELOG.md` describes the release
- [ ] CI green on `main`
- [ ] Validation records in `docs/validation/` still bind to reachable commits
- [ ] `production_ready` statement in `docs/PRODUCTION_READINESS.md` reflects reality
- [ ] Tag pushed; `release.yml` green on both architectures
- [ ] `REQUIRE_SIGNED_RELEASE` explicitly matches the documented signed or unsigned policy
- [ ] Downloaded assets verified with the four checks above
