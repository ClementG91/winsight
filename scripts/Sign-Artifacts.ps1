<#
.SYNOPSIS
    Authenticode-signs WinSight executables, or reports the absence of a certificate loudly.

.DESCRIPTION
    A security tool that ships unsigned binaries asks its users to run an unverified executable with
    Administrator rights. That is a real cost, so this script never fails quietly and never pretends:
    it either signs and then independently verifies every file, or it states plainly that the output
    is UNSIGNED.

    Signing happens before archives are compressed and before any checksum is computed, so the
    published hashes cover the signed bytes. Signing afterwards would silently invalidate them.

    A code-signing certificate is an external resource this repository cannot contain. Supply one
    through the environment (see docs/RELEASE.md):

      WINSIGHT_SIGNING_CERT_BASE64      base64 of a PFX containing the signing key
      WINSIGHT_SIGNING_CERT_PASSWORD    that PFX's password

    Absence is a supported state - unsigned development and community builds still work - but it is
    always announced, and `-RequireSignature` turns it into a hard failure for a real release.

.EXAMPLE
    ./Sign-Artifacts.ps1 -Path out/release/package/win-x64/winsight.exe
    ./Sign-Artifacts.ps1 -Path $exes -RequireSignature
#>
[CmdletBinding()]
param(
    # Files to sign. Missing paths are an error: silently signing nothing is the failure mode this
    # whole script exists to prevent.
    [Parameter(Mandatory)]
    [string[]]$Path,

    [string]$CertificateBase64 = $env:WINSIGHT_SIGNING_CERT_BASE64,

    [string]$CertificatePassword = $env:WINSIGHT_SIGNING_CERT_PASSWORD,

    # RFC3161 timestamp authority. Timestamping is not optional: without it every signature stops
    # validating the day the certificate expires.
    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    # Turns "no certificate" from an announced skip into a failure. Use for tagged releases.
    [switch]$RequireSignature
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Find-SignTool {
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path $env:ProgramFiles 'Windows Kits\10\bin'))
    $candidates = New-Object System.Collections.ArrayList
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($tool in (Get-ChildItem -LiteralPath $root -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue)) {
            # Prefer a signtool whose architecture matches the host so it runs natively on Arm64.
            [void]$candidates.Add($tool.FullName)
        }
    }
    if ($candidates.Count -eq 0) { return $null }
    $preferred = switch ($env:PROCESSOR_ARCHITECTURE) {
        'ARM64' { 'arm64' }
        'AMD64' { 'x64' }
        default { 'x86' }
    }
    $match = $candidates | Where-Object { $_ -match [regex]::Escape("\$preferred\") } | Select-Object -Last 1
    if ($match) { return $match }
    return ($candidates | Select-Object -Last 1)
}

$resolved = New-Object System.Collections.ArrayList
foreach ($item in $Path) {
    if (-not (Test-Path -LiteralPath $item)) {
        throw "Cannot sign a file that does not exist: $item"
    }
    [void]$resolved.Add((Resolve-Path -LiteralPath $item).Path)
}
if ($resolved.Count -eq 0) {
    throw 'No files were supplied to sign.'
}

$haveCertificate = -not ([string]::IsNullOrWhiteSpace($CertificateBase64))
if (-not $haveCertificate) {
    if ($RequireSignature) {
        throw 'A signing certificate is required for this build but WINSIGHT_SIGNING_CERT_BASE64 is not set.'
    }
    Write-Host '[SIGNING] SKIPPED - no certificate configured.'
    Write-Host ('[SIGNING] {0} file(s) will ship UNSIGNED. Windows will warn users on first run.' -f $resolved.Count)
    Write-Host '[SIGNING] See docs/RELEASE.md to supply a certificate.'
    exit 0
}

$signTool = Find-SignTool
if (-not $signTool) {
    throw 'A signing certificate was supplied but signtool.exe was not found. Install the Windows SDK signing tools.'
}
Write-Host ('[SIGNING] tool: {0}' -f $signTool)

$pfxPath = Join-Path ([IO.Path]::GetTempPath()) ("winsight-signing-" + [guid]::NewGuid().ToString('N') + '.pfx')
$signed = 0
try {
    try {
        [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($CertificateBase64))
    }
    catch {
        throw 'WINSIGHT_SIGNING_CERT_BASE64 is not valid base64.'
    }

    foreach ($file in $resolved) {
        $signArguments = @(
            'sign',
            '/fd', 'SHA256',
            '/td', 'SHA256',
            '/tr', $TimestampUrl,
            '/f', $pfxPath)
        if (-not [string]::IsNullOrWhiteSpace($CertificatePassword)) {
            $signArguments += @('/p', $CertificatePassword)
        }
        $signArguments += $file

        # The password is in $signArguments, so the command line is never echoed.
        & $signTool @signArguments | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "signtool failed to sign $file (exit $LASTEXITCODE)."
        }

        # Independent verification. A zero exit from `sign` says the tool ran; only `verify` says the
        # file now carries a chain-valid, timestamped Authenticode signature.
        & $signTool 'verify' '/pa' '/all' $file | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "signtool signed $file but verification failed (exit $LASTEXITCODE)."
        }

        $signed++
        Write-Host ('[SIGNING] signed and verified: {0}' -f (Split-Path -Leaf $file))
    }
}
finally {
    if (Test-Path -LiteralPath $pfxPath) {
        Remove-Item -LiteralPath $pfxPath -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ('[SIGNING] OK - {0} file(s) signed, timestamped and verified.' -f $signed)
exit 0
