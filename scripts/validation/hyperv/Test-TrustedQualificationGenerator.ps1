# Run without elevation. The fixture is an isolated temporary repository, never the user's index.
$ErrorActionPreference = 'Stop'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('winsight-launcher-test-' + [Guid]::NewGuid().ToString('N'))
$generator = Join-Path $PSScriptRoot 'New-TrustedQualificationLauncher.ps1'
$git = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$failures = 0; $checks = 0
function Check([bool]$Passed, [string]$Name) {
    $script:checks++
    if (-not $Passed) { $script:failures++ }
    '{0} {1}' -f $(if ($Passed) { 'PASS' } else { 'FAIL' }), $Name
}
function Git([string[]]$Arguments) {
    & $git -C $fixture -c core.autocrlf=false -c commit.gpgsign=false -c core.hooksPath=empty-hooks @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Fixture git command failed: $Arguments" }
}
function Throws([scriptblock]$Action) { try { & $Action | Out-Null; return $false } catch { return $true } }
try {
    [void][IO.Directory]::CreateDirectory($fixture)
    [void][IO.Directory]::CreateDirectory((Join-Path $fixture 'empty-hooks'))
    $destination = Join-Path $fixture 'scripts\validation\hyperv'
    [void][IO.Directory]::CreateDirectory((Join-Path $destination 'guest'))
    Import-Module (Join-Path $PSScriptRoot 'QualificationProvenance.psm1') -Force
    foreach ($relative in (@(Get-QualificationHarnessFiles) + 'TrustedQualificationBootstrap.ps1')) {
        [IO.File]::Copy((Join-Path $PSScriptRoot $relative), (Join-Path $destination $relative))
    }
    Git @('init', '--quiet', '--template=empty-hooks')
    Git @('add', '--', 'scripts')
    Git @('-c', 'user.name=WinSight test', '-c', 'user.email=tests@invalid.example', 'commit', '--quiet', '-m', 'fixture')
    $commit = (& $git -C $fixture rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Fixture commit unavailable.' }
    $one = Join-Path $fixture 'one.ps1'
    $two = Join-Path $fixture 'two.ps1'
    & $generator -Repository $fixture -Commit $commit -OutputPath $one | Out-Null
    [IO.File]::WriteAllText((Join-Path $destination 'WinSightQualRunner.ps1'), 'throw "dirty checkout must never be bundled"')
    & $generator -Repository $fixture -Commit $commit -OutputPath $two | Out-Null
    $first = [IO.File]::ReadAllBytes($one)
    $second = [IO.File]::ReadAllBytes($two)
    Check ([Convert]::ToBase64String($first) -ceq [Convert]::ToBase64String($second)) 'bundle is deterministic and ignores modified worktree files'
    $line = [IO.File]::ReadAllText("$one.sha256").Trim()
    $expected = (Get-FileHash -LiteralPath $one -Algorithm SHA256).Hash.ToLowerInvariant() + '  one.ps1'
    Check ($line -ceq $expected) 'checksum binds the generated launcher and filename'
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($one, [ref]$tokens, [ref]$errors)
    Check ($errors.Count -eq 0) 'generated launcher parses under Windows PowerShell 5.1'
    Check (Throws { & $generator -Repository $fixture -Commit $commit -OutputPath $one }) 'existing output is never overwritten'
    Check (Throws { & $generator -Repository $fixture -Commit ('0' * 40) -OutputPath (Join-Path $fixture 'unknown.ps1') }) 'unknown commit rejected'
    Check (-not (Test-Path -LiteralPath (Join-Path $fixture 'unknown.ps1'))) 'rejected commit creates no output'
    Check (Throws { & $generator -Repository $fixture -Commit 'HEAD' -OutputPath (Join-Path $fixture 'ref.ps1') }) 'mutable ref rejected'
}
finally {
    $resolved = [IO.Path]::GetFullPath($fixture)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notmatch '^winsight-launcher-test-[0-9a-f]{32}$') { throw 'Unexpected fixture cleanup path.' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
"$checks checks, $failures failures."
if ($failures -gt 0) { exit 1 }
exit 0
