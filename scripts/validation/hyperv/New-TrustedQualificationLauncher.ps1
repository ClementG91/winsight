# Build without elevation, in an independently trusted review context. The resulting digest is a
# trust anchor only when the operator authenticates it outside the writable qualification checkout.
[CmdletBinding()]
param(
    [string]$Repository,
    [Parameter(Mandatory)]
    [ValidateScript({ $_ -cmatch '^[0-9a-f]{40}$' })]
    [string]$Commit,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $Repository) {
    $Repository = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
}
$Repository = (Resolve-Path -LiteralPath $Repository).ProviderPath
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
if ([IO.Path]::GetExtension($OutputPath) -ine '.ps1') {
    throw 'OutputPath must name a standalone .ps1 launcher.'
}
$checksumPath = "$OutputPath.sha256"
if ([IO.File]::Exists($OutputPath) -or [IO.Directory]::Exists($OutputPath) -or
    [IO.File]::Exists($checksumPath) -or [IO.Directory]::Exists($checksumPath)) {
    throw 'The launcher or checksum already exists. Choose a new OutputPath; outputs are never overwritten.'
}

$git = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$maximumFileBytes = 1MB
$maximumBundleBytes = 16MB

function Read-GitBytes([string]$Arguments, [int]$MaximumBytes) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $git
    $start.WorkingDirectory = $Repository
    # Arguments are fixed switches plus validated hex IDs and the fixed path allowlist below.
    $start.Arguments = '--no-pager --no-replace-objects ' + $Arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables['GIT_OPTIONAL_LOCKS'] = '0'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $bytes = [IO.MemoryStream]::new()
    try {
        if (-not $process.Start()) { throw 'Unable to start git.' }
        $errorText = $process.StandardError.ReadToEndAsync()
        $buffer = [byte[]]::new(8192)
        while (($count = $process.StandardOutput.BaseStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($bytes.Length + $count -gt $MaximumBytes) {
                $process.Kill()
                throw "Committed input exceeds the $MaximumBytes-byte limit."
            }
            $bytes.Write($buffer, 0, $count)
        }
        $process.WaitForExit()
        $diagnostic = $errorText.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "Unable to read committed input (git exit $($process.ExitCode)): $($diagnostic.Trim())"
        }
        # Never pass Git blob data through PowerShell's native-command text decoder.
        return ,$bytes.ToArray()
    }
    finally {
        $bytes.Dispose()
        $process.Dispose()
    }
}

function Get-HexHash([byte[]]$Bytes, [string]$Algorithm) {
    $hash = [Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    try { return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

$resolved = $utf8.GetString((Read-GitBytes "rev-parse --verify $Commit`^{commit}" 256)).Trim()
if ($resolved -cne $Commit) { throw 'Commit must resolve to that exact immutable commit, not a tag or abbreviation.' }

# This allowlist intentionally contains data only: building the launcher must not import or execute
# even the committed harness. The contract tests compare it with the provenance module's inventory.
$relativePaths = @(
    'WinSightHyperV.psm1',
    'QualificationProvenance.psm1',
    'WinSightQualRunner.ps1',
    'Invoke-HyperVQualification.ps1',
    'Invoke-HyperVNetworkLogon.ps1',
    'New-WinSightHyperVVm.ps1',
    'New-WinSightControlVm.ps1',
    'Protect-WinSightVmStorage.ps1',
    'Verify-QualificationProvenance.ps1',
    'guest\run-guest-checks.ps1',
    'guest\control-network-logon.ps1',
    'guest\qualify.ps1',
    'guest\operator-automation.ps1',
    'guest\NetworkProbeCredential.psm1'
)
$files = @(
    foreach ($relative in $relativePaths) {
        $path = 'scripts/validation/hyperv/' + $relative.Replace('\', '/')
        $content = Read-GitBytes "show --no-textconv ${Commit}:$path" $maximumFileBytes
        $blob = $utf8.GetString((Read-GitBytes "rev-parse --verify ${Commit}:$path" 256)).Trim()
        $header = [Text.Encoding]::ASCII.GetBytes("blob $($content.Length)`0")
        $blobBytes = [byte[]]::new($header.Length + $content.Length)
        [Buffer]::BlockCopy($header, 0, $blobBytes, 0, $header.Length)
        [Buffer]::BlockCopy($content, 0, $blobBytes, $header.Length, $content.Length)
        if ($blob -cnotmatch '^[0-9a-f]{40}$' -or (Get-HexHash $blobBytes 'SHA1') -cne $blob) {
            throw "Committed blob identity mismatch: $relative"
        }
        [ordered]@{
            relative = $relative
            sha256 = Get-HexHash $content 'SHA256'
            blob = $blob
            contentBase64 = [Convert]::ToBase64String($content)
        }
    }
)
$payload = [ordered]@{ schemaVersion = 1; commit = $Commit; files = $files } | ConvertTo-Json -Depth 5 -Compress
$payloadBase64 = [Convert]::ToBase64String($utf8.GetBytes($payload))
$templatePath = 'scripts/validation/hyperv/TrustedQualificationBootstrap.ps1'
$template = $utf8.GetString((Read-GitBytes "show --no-textconv ${Commit}:$templatePath" $maximumFileBytes))
$token = '__WINSIGHT_HARNESS_PAYLOAD_BASE64__'
if (($template.Split(@($token), [StringSplitOptions]::None).Length - 1) -ne 1) {
    throw 'Committed bootstrap template must contain exactly one payload token.'
}
$launcher = $utf8.GetBytes($template.Replace($token, $payloadBase64).Replace("`r`n", "`n").Replace("`r", "`n"))
if ($launcher.Length -gt $maximumBundleBytes) { throw 'Generated launcher exceeds the 16 MiB bundle limit.' }
$digest = Get-HexHash $launcher 'SHA256'
$checksum = $utf8.GetBytes("$digest  $([IO.Path]::GetFileName($OutputPath))`n")

# CreateNew is the race-resistant overwrite guard. Generate and validate everything before reserving
# either output. If filesystem creation fails, do not remove or replace any concurrently created file.
$launcherStream = $null
$checksumStream = $null
try {
    $launcherStream = [IO.File]::Open($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $checksumStream = [IO.File]::Open($checksumPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $launcherStream.Write($launcher, 0, $launcher.Length)
    $checksumStream.Write($checksum, 0, $checksum.Length)
    $launcherStream.Flush($true)
    $checksumStream.Flush($true)
}
finally {
    if ($null -ne $checksumStream) { $checksumStream.Dispose() }
    if ($null -ne $launcherStream) { $launcherStream.Dispose() }
}
Write-Output "Created $OutputPath from commit $Commit"
Write-Output "SHA256 $digest"
Write-Warning 'Authenticate this digest from an independently trusted review context before elevation. A digest generated beside a writable checkout is not proof of trust.'
