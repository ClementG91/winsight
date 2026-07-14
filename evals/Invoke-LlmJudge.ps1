#requires -Version 7.0
<#
.SYNOPSIS
    Runs a WinSight scan and scores its AI-facing output with an LLM-as-a-judge.

.DESCRIPTION
    Local-first and opt-in. The scan itself uses the CLI --json contract and performs
    no network call. The optional judging step is the ONLY part that contacts a model,
    and only when you supply the command that talks to it. Prompts and verdicts are
    written under evals/out and evals/results, which are git-ignored.

.PARAMETER WinSight
    Path to winsight.exe. Defaults to the Release build if present.

.PARAMETER Scanner
    CLI subcommand to evaluate (e.g. all, persistence, net, certs). Default: all.

.PARAMETER JudgeCommand
    A command that reads the judge prompt on stdin and writes the verdict JSON to
    stdout (for example your own model CLI). Defaults to $env:WINSIGHT_JUDGE_CMD.
    When empty, the prompt is written for manual judging and no model is contacted.

.EXAMPLE
    ./evals/Invoke-LlmJudge.ps1 -Scanner certs
    $env:WINSIGHT_JUDGE_CMD = 'my-model-cli --model some-judge'
    ./evals/Invoke-LlmJudge.ps1 -Scanner all
#>
[CmdletBinding()]
param(
    [string]$WinSight,
    [string]$Scanner = 'all',
    [string]$JudgeCommand = $env:WINSIGHT_JUDGE_CMD
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $PSScriptRoot 'out'
$resultsDir = Join-Path $PSScriptRoot 'results'
New-Item -ItemType Directory -Force -Path $outDir, $resultsDir | Out-Null

if (-not $WinSight) {
    $candidate = Join-Path $root 'src/WinSight.Cli/bin/Release/net10.0-windows10.0.19041.0/winsight.exe'
    if (-not (Test-Path $candidate)) {
        throw "winsight.exe not found. Build the CLI first or pass -WinSight. Looked at: $candidate"
    }
    $WinSight = $candidate
}

$rubricPath = Join-Path $PSScriptRoot 'rubric.md'
if (-not (Test-Path $rubricPath)) { throw "Missing rubric at $rubricPath" }
$rubric = Get-Content $rubricPath -Raw

Write-Host "Running WinSight '$Scanner' (--json, local, no network)..."
$report = & $WinSight $Scanner --json
if ($LASTEXITCODE -notin 0, 1) {
    # 0 = nothing notable, 1 = notable findings; anything else is a real failure.
    throw "WinSight exited with code $LASTEXITCODE."
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$prompt = @"
You are grading a WinSight security report for an AI client. Apply this rubric exactly
and return only the JSON verdict it specifies.

# Rubric
$rubric

# Report under test (WinSight --json)
$report
"@

$promptPath = Join-Path $outDir "$Scanner-$stamp.prompt.txt"
Set-Content -Path $promptPath -Value $prompt -Encoding utf8
Write-Host "Judge prompt written: $promptPath"

if ([string]::IsNullOrWhiteSpace($JudgeCommand)) {
    Write-Host "No judge command configured (set -JudgeCommand or `$env:WINSIGHT_JUDGE_CMD)."
    Write-Host "The prompt above is ready for manual judging. No model was contacted."
    return
}

Write-Host "Judging with: $JudgeCommand"
$verdict = $prompt | & pwsh -NoProfile -Command $JudgeCommand
$verdictPath = Join-Path $resultsDir "$Scanner-$stamp.verdict.json"
Set-Content -Path $verdictPath -Value $verdict -Encoding utf8
Write-Host "Verdict written: $verdictPath"
$verdict
