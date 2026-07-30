# Code Signing Policy

This document states who can cause a WinSight binary to be signed, under what review, and what a
signature does and does not prove. It exists because "signed" is a claim users are asked to trust, and
an unexplained signature is just a warning they no longer see.

For how a release is cut, hashed and attested, see [RELEASE.md](RELEASE.md).

## Current signing status

**WinSight releases are intentionally distributed without Authenticode for now.** Windows shows an
unknown-publisher warning on first run, and that warning is accurate.

SignPath Foundation declined the project's free-program application on 2026-07-29 because the project
does not yet have enough public adoption and independent visibility. SignPath explicitly described
this as a visibility decision, not a judgment of software quality. A paid subscription was not chosen.
The project may reapply after it has stronger external adoption signals.

The repository variable is therefore deliberately set to
`REQUIRE_SIGNED_RELEASE=false`. The release workflow rejects an absent or malformed value and writes
the unsigned policy into the run summary. It also forces `Build-Release.ps1 -DisableSignature`, so a
residual credential cannot silently sign an unsigned-policy release. The signed build path remains
implemented and testable for a future certificate, but it is not presented as an active control.

What every release *does* carry today:

- **SHA-256 checksums** for every artifact, generated in the build job and **re-verified in a separate
  job** before publication.
- **GitHub build provenance attestation** - a cryptographic statement, signed by GitHub's OIDC
  identity, binding the artifact to the workflow, repository and commit that produced it.
- **SBOM attestation** - the dependency inventory, attested the same way.

Provenance is not a substitute for Authenticode. It proves *where the bytes came from*; Authenticode
would provide a publisher identity to Windows. Users must verify the SHA-256 and GitHub attestations
before running a release and must expect the unknown-publisher warning.

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
- **Any future production signing happens only in CI**, from a tagged commit on `main`, in a workflow
  whose definition is in this repository and covered by the same review requirements as any other
  file.
- **No signing key ever exists on a developer machine.** There is no local signing path, so a
  compromised workstation cannot produce a signed WinSight binary.
- **The tag must match the project version.** `release.yml` refuses to build when
  `Directory.Build.props` and the tag disagree, so a mistyped tag stops the release rather than
  shipping a mislabelled artifact.

If this project ever gains a second maintainer, Reviewer and Approver will be separated from Author
and this table will say so.

## What would be signed

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

Every future signed binary would carry the stable product identity - product name, company, copyright
and version - set centrally in `Directory.Build.props` rather than derived from an assembly name. The
current unsigned binaries expose that metadata but have no verified Windows publisher identity.

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
