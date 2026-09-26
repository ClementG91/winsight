# Nonprivileged behavioral tests of the two pre-execution trust checks. No download or installation.
$ErrorActionPreference = 'Stop'
$failures = 0
$checks = 0
function Check([bool]$Passed, [string]$Name) {
    $script:checks++
    if (-not $Passed) { $script:failures++ }
    '{0} {1}' -f $(if ($Passed) { 'PASS' } else { 'FAIL' }), $Name
}
function Throws([scriptblock]$Action) { try { & $Action | Out-Null; return $false } catch { return $true } }
function Hash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
# Load function definitions only: never execute the bootstrap's privileged top-level code.
foreach ($name in 'Invoke-VerifiedQualificationLauncher.ps1', 'TrustedQualificationBootstrap.ps1') {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name), [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw ($errors | Out-String) }
    foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($function.Extent.Text))
    }
}
$canary = [Text.Encoding]::UTF8.GetBytes('param($Destination, $LauncherSha256) "verified-canary"')
$digest = Hash $canary
Check ((Invoke-VerifiedQualificationBytes -Bytes $canary -ExpectedSha256 $digest -Destination 'unused') -eq 'verified-canary') 'authenticated bytes execute'
$changed = [byte[]]$canary.Clone(); $changed[0] = $changed[0] -bxor 1
Check (Throws { Invoke-VerifiedQualificationBytes -Bytes $changed -ExpectedSha256 $digest -Destination 'unused' }) 'substituted launcher rejected before execution'
Check (Throws { Invoke-VerifiedQualificationBytes -Bytes $canary -ExpectedSha256 ('0' * 64) -Destination 'unused' }) 'wrong external anchor rejected'
Check (Throws { Invoke-VerifiedQualificationBytes -Bytes ([byte[]]@()) -ExpectedSha256 $digest -Destination 'unused' }) 'empty launcher rejected'
$invalidUtf8 = [byte[]]@(0xC0, 0xAF)
Check (Throws { Invoke-VerifiedQualificationBytes -Bytes $invalidUtf8 -ExpectedSha256 (Hash $invalidUtf8) -Destination 'unused' }) 'invalid UTF8 rejected despite matching digest'

$content = [Text.Encoding]::UTF8.GetBytes('# authenticated test data')
function Payload([string]$Relative = 'WinSightHyperV.psm1', [string]$Sha256 = (Hash $content)) {
    $header = [Text.Encoding]::ASCII.GetBytes("blob $($content.Length)`0")
    $sha1 = [Security.Cryptography.SHA1]::Create()
    try { $blob = [BitConverter]::ToString($sha1.ComputeHash([byte[]]($header + $content))).Replace('-', '').ToLowerInvariant() }
    finally { $sha1.Dispose() }
    $value = [ordered]@{ schemaVersion = 1; commit = ('c' * 40); files = @(
            [ordered]@{ relative = $Relative; sha256 = $Sha256; blob = $blob; contentBase64 = [Convert]::ToBase64String($content) }
        ) }
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Depth 5 -Compress)))
}
$valid = Read-AuthenticatedQualificationPayload -Base64 (Payload)
Check ($valid.Files.Count -eq 1 -and $valid.Commit -eq ('c' * 40)) 'authenticated payload parses without execution'
Check (Throws { Read-AuthenticatedQualificationPayload -Base64 (Payload -Sha256 ('0' * 64)) }) 'payload byte substitution rejected'
foreach ($path in '..\outside.ps1', 'C:\outside.ps1', '\\server\share\x.ps1', 'guest/../x.ps1', 'guest\x.ps1:stream') {
    Check (Throws { Read-AuthenticatedQualificationPayload -Base64 (Payload -Relative $path) }) "unsafe bundle path rejected: $path"
}
$duplicate = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Payload))) | ConvertFrom-Json
$duplicate.files = @($duplicate.files[0], $duplicate.files[0])
$duplicate64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($duplicate | ConvertTo-Json -Depth 5 -Compress)))
Check (Throws { Read-AuthenticatedQualificationPayload -Base64 $duplicate64 }) 'duplicate bundle paths rejected'
"$checks checks, $failures failures."
if ($failures -gt 0) { exit 1 }
exit 0
