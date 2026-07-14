[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [Parameter(Mandatory)]
    [ValidateSet("x64", "arm64")]
    [string]$Architecture
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$resolvedPath = (Resolve-Path -LiteralPath $Path).Path
$expectedMachine = switch ($Architecture)
{
    "x64" { 0x8664 }
    "arm64" { 0xAA64 }
}

$stream = [System.IO.File]::OpenRead($resolvedPath)
$reader = [System.IO.BinaryReader]::new($stream)
try
{
    if ($reader.ReadUInt16() -ne 0x5A4D)
    {
        throw "$resolvedPath is not a PE file (missing MZ header)."
    }

    $stream.Position = 0x3C
    $peOffset = $reader.ReadUInt32()
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x00004550)
    {
        throw "$resolvedPath is not a PE file (missing PE signature)."
    }

    $actualMachine = $reader.ReadUInt16()
    if ($actualMachine -ne $expectedMachine)
    {
        throw ("Expected {0} PE machine 0x{1:X4}, got 0x{2:X4} for {3}." -f `
            $Architecture, $expectedMachine, $actualMachine, $resolvedPath)
    }
}
finally
{
    $reader.Dispose()
    $stream.Dispose()
}

Write-Output "$resolvedPath is a valid $Architecture PE image."
