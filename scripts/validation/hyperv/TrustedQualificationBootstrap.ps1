# Generated with the reviewed harness embedded as data. Authenticate the complete generated file
# externally before executing it. This template alone is not an installable launcher.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$LauncherSha256
)

# Defense in depth: the operator's authenticated entry functions set this before invoking us too.
$env:PSModulePath = [IO.Path]::Combine([Environment]::GetFolderPath('System'), 'WindowsPowerShell\v1.0\Modules')

function Read-AuthenticatedQualificationPayload {
    param([Parameter(Mandatory)][string]$Base64)
    if ($Base64.Length -gt 16MB) { throw 'Harness payload exceeds its size limit.' }
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $payload = $utf8.GetString([Convert]::FromBase64String($Base64)) | ConvertFrom-Json
    if ($payload.schemaVersion -ne 1 -or [string]$payload.commit -cnotmatch '^[0-9a-f]{40}$' -or
        @($payload.files).Count -eq 0 -or @($payload.files).Count -gt 32) { throw 'Invalid harness payload header.' }
    $files = @{}
    $total = 0L
    foreach ($file in $payload.files) {
        $relative = [string]$file.relative
        if ($relative -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*(\\[A-Za-z0-9][A-Za-z0-9._-]*)*$' -or
            $relative -match '(^|\\)\.\.?(\\|$)' -or $files.ContainsKey($relative) -or
            [string]$file.sha256 -notmatch '^[0-9a-fA-F]{64}$' -or
            [string]$file.blob -notmatch '^[0-9a-fA-F]{40}$' -or
            ([string]$file.contentBase64).Length -gt 2MB) { throw 'Invalid or duplicate harness file.' }
        $bytes = [Convert]::FromBase64String([string]$file.contentBase64)
        $total += $bytes.Length
        if ($bytes.Length -gt 1MB -or $total -gt 12MB) { throw 'Harness files exceed their size limit.' }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '') }
        finally { $sha.Dispose() }
        if ($hash -ine $file.sha256) { throw 'Harness file SHA256 mismatch.' }
        $header = [Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)`0")
        $sha1 = [Security.Cryptography.SHA1]::Create()
        try { $blob = [BitConverter]::ToString($sha1.ComputeHash([byte[]]($header + $bytes))).Replace('-', '') }
        finally { $sha1.Dispose() }
        if ($blob -ine $file.blob) { throw 'Harness git blob mismatch.' }
        $files[$relative] = [pscustomobject]@{ Relative = $relative; Sha256 = $hash; Blob = $blob; Bytes = $bytes }
    }
    [pscustomobject]@{ Commit = $payload.commit; Files = $files }
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The independently authenticated installer must run in the operator elevated console.'
}
if ($Destination -notmatch '^[A-Za-z]:\\' -or $Destination.StartsWith('\\')) {
    throw 'Destination must be an absolute local drive path.'
}
$Destination = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
if (Test-Path -LiteralPath $Destination) { throw 'Choose a new protected destination; an existing installation is never overwritten.' }
$bundle = Read-AuthenticatedQualificationPayload -Base64 '__WINSIGHT_HARNESS_PAYLOAD_BASE64__'
$utf8 = New-Object Text.UTF8Encoding($false, $true)
# Every imported byte is already in the externally authenticated buffer. No module is loaded from
# the checkout, PATH, the current directory, or a source filename that can be swapped after hashing.
foreach ($moduleName in 'WinSightHyperV.psm1', 'QualificationProvenance.psm1') {
    if (-not $bundle.Files.ContainsKey($moduleName)) { throw "Missing authenticated module: $moduleName" }
    $module = New-Module -Name ([IO.Path]::GetFileNameWithoutExtension($moduleName)) -ScriptBlock (
        [scriptblock]::Create($utf8.GetString($bundle.Files[$moduleName].Bytes).TrimStart([char]0xFEFF)))
    Import-Module $module -Force
}
$entries = @($bundle.Files.Values | ForEach-Object { [pscustomobject]@{ Relative = $_.Relative; Sha256 = $_.Sha256; Blob = $_.Blob } })
if (-not (Test-QualificationManifest -Entries $entries -ExpectedPaths @(Get-QualificationHarnessFiles))) {
    throw 'The authenticated bundle does not contain the complete reviewed harness.'
}
Assert-ProtectedAncestors -Path $Destination
Set-AdministratorsDefaultOwner
New-ProtectedDirectory -Path $Destination -UsersRead
foreach ($relative in (Get-QualificationHarnessFiles)) {
    $target = Join-Path $Destination $relative
    $parent = Split-Path -Parent $target
    if ($parent -ne $Destination) { New-ProtectedDirectory -Path $parent -UsersRead }
    $writer = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = $bundle.Files[$relative].Bytes
        $writer.Write($bytes, 0, $bytes.Length)
        $writer.Flush($true)
    }
    finally { $writer.Dispose() }
}
$receipt = [ordered]@{
    schemaVersion = 1
    harnessCommit = $bundle.Commit
    launcherSha256 = $LauncherSha256.ToLowerInvariant()
    installedUtc = [DateTime]::UtcNow.ToString('o')
    files = @($entries | Sort-Object Relative)
}
$receiptBytes = $utf8.GetBytes(($receipt | ConvertTo-Json -Depth 5))
$writer = [IO.File]::Open((Join-Path $Destination 'bootstrap-provenance.json'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $writer.Write($receiptBytes, 0, $receiptBytes.Length); $writer.Flush($true) }
finally { $writer.Dispose() }
Assert-ProtectedPath -Path $Destination -Recurse
Write-Output "Installed authenticated harness $($bundle.Commit) into $Destination"
Write-Output 'Launch the runner and verifier only from this protected installation; use explicit qualification paths.'
