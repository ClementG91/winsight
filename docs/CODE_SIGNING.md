# Code Signing Policy

This document states who can cause a WinSight binary to be signed, under what review, and what a
signature does and does not prove. It exists because "signed" is a claim users are asked to trust, and
an unexplained signature is just a warning they no longer see.

For how a release is cut, hashed and attested, see [RELEASE.md](RELEASE.md).

## Current signing status

**WinSight releases are not yet Authenticode-signed.** This is stated plainly rather than buried:
Windows shows an unknown-publisher warning on first run, and that warning is accurate.

WinSight has **applied to the [SignPath Foundation](https://signpath.org/)**, which provides free code
signing to open-source projects through the SignPath.io platform. If the application is granted:

- Release binaries will be signed by **SignPath.io**, with a certificate issued in **SignPath
  Foundation's name** — not in the maintainer's. A SignPath-issued signature attests that the binary
  came from this project's reviewed release pipeline under the Foundation's terms; it is not a
  statement by the Foundation about the software's quality or fitness.
- The certificate may be **revoked by the Foundation** if this project violates those terms.
- No signing key will exist in this repository or on any developer machine. Signing is requested by the
  release workflow and performed on SignPath's infrastructure.
- This document and the README will be updated to describe the arrangement in the present tense, and
  the roles below become the roles SignPath holds this project to.

Until then, the checksums and attestations described below are the only integrity evidence, and this
document says so rather than implying a signature that does not exist.

What every release *does* carry today:

- **SHA-256 checksums** for every artifact, generated in the build job and **re-verified in a separate
  job** before publication.
- **GitHub build provenance attestation** — a cryptographic statement, signed by GitHub's OIDC
  identity, binding the artifact to the workflow, repository and commit that produced it.
- **SBOM attestation** — the dependency inventory, attested the same way.

Provenance is not a substitute for Authenticode. It proves *where the bytes came from*; Authenticode
proves *who stands behind them* to the operating system. Both are wanted; only one is in place.

The repository variable `REQUIRE_SIGNED_RELEASE=true` makes a missing certificate a **hard failure**,
so a release cannot quietly lose a signature it once had. See
[RELEASE.md](RELEASE.md#authenticode-signing).

## Who may authorise a signature

WinSight is maintained by one person. Inventing a committee here would be exactly the kind of
overstated control this project criticises elsewhere, so the roles are stated as they actually are:

| Role | Held by | Meaning |
|---|---|---|
| **Author** | Clément Genest (`@ClementG91`) | Writes and modifies code |
| **Reviewer** | Clément Genest (`@ClementG91`) | Approves pull requests |
| **Approver** | Clément Genest (`@ClementG91`) | Authorises a signing request |

**This is a single point of trust, and it is disclosed rather than dressed up.** The compensating
controls are technical, not organisational:

- **Multi-factor authentication** is enabled on the maintainer's GitHub account.
- **Signed commits are required on `main`**, and the requirement binds the maintainer's own account:
  `enforce_admins` is enabled, so the only account able to bypass the rule cannot. A control that
  exempts the one actor capable of breaking it is theatre.
- **Signing happens only in CI**, from a tagged commit on `main`, in a workflow whose definition is in
  this repository and covered by the same review and signing requirements as any other file.
- **No signing key ever exists on a developer machine.** There is no local signing path, so a
  compromised workstation cannot produce a signed WinSight binary.
- **The tag must match the project version.** `release.yml` refuses to build when
  `Directory.Build.props` and the tag disagree, so a mistyped tag stops the release rather than
  shipping a mislabelled artifact.

If this project ever gains a second maintainer, Reviewer and Approver will be separated from Author
and this table will say so.

## What is signed

- **Only WinSight's own binaries**, built in CI from this repository's source at a tagged commit.
- **Never third-party or upstream binaries.** WinSight ships self-contained .NET applications; the
  runtime components inside them are Microsoft's, signed by Microsoft, and are not re-signed.
- **Never anything built anywhere but this repository's release workflow.**

Signing runs inside `Build-Release.ps1` deliberately **before** archives are compressed and **before**
any checksum is computed, so every published hash describes the signed bytes. Signing afterwards would
leave every published hash describing bytes that no longer exist.

`Sign-Artifacts.ps1` then runs `signtool verify /pa /all` on every file it signed. A zero exit from
`signtool sign` only says the tool ran; it does not say the file now carries a chain-valid signature.

## What a WinSight signature would mean

- **It would mean:** these bytes were produced by this project's release workflow, from a tagged commit
  on `main`, and have not been altered since.
- **It would not mean:** the software is free of defects, that any third party has audited it, or that
  the operating system vendor endorses it.

## Binary metadata

Every signed binary carries a stable product identity — product name, company, copyright and version —
set centrally in `Directory.Build.props` rather than derived from an assembly name. A signing policy
that pins expected metadata is only meaningful if that metadata is deliberate, and it is what Windows
shows the user in the UAC and SmartScreen prompts.

## Reporting a problem with a signature

If you find a binary that claims to be WinSight and whose signature or provenance does not verify, do
**not** open a public issue. Use private reporting as described in [SECURITY.md](../SECURITY.md).

## Verifying a release yourself

Do not take this document's word for it. Every release can be checked independently:

```powershell
# Checksum
(Get-FileHash .\winsight-vX.Y.Z-win-x64-setup.exe -Algorithm SHA256).Hash

# Build provenance, against this repository
gh attestation verify .\winsight-vX.Y.Z-win-x64-setup.exe --repo ClementG91/winsight
```

Full verification instructions: [RELEASE.md](RELEASE.md).
