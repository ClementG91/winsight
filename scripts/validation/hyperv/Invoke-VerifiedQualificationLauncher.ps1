# TRUST ROOT: copy these functions from the independently reviewed repository/release into a fresh
# elevated Windows PowerShell 5.1 -NoProfile console. Never elevate this file from a mutable checkout.
# ExpectedSha256 must come from the reviewed release/attestation, not a neighboring local .sha256.
function Invoke-VerifiedQualificationBytes {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$Destination
    )
    $env:PSModulePath = [IO.Path]::Combine([Environment]::GetFolderPath('System'), 'WindowsPowerShell\v1.0\Modules')
    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt 16MB) { throw 'Launcher size is outside the permitted range.' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '') }
    finally { $sha.Dispose() }
    if ($actual -ine $ExpectedSha256) { throw 'Launcher SHA256 does not match the independently trusted digest.' }
    # The operator uses a fresh -NoProfile console. Exclude user-controlled module search roots
    # before authenticated code invokes standard Windows cmdlets through module auto-loading.
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    # Execute the very buffer authenticated above: no pathname is reopened after verification.
    & ([scriptblock]::Create($utf8.GetString($Bytes))) -Destination $Destination -LauncherSha256 $actual
}

function Install-WinSightTrustedHarness {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^https://github\.com/ClementG91/winsight/releases/download/v[0-9]+\.[0-9]+\.[0-9]+/winsight-v[0-9]+\.[0-9]+\.[0-9]+-qualification\.ps1$')]
        [string]$LauncherUri,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$Destination
    )
    $env:PSModulePath = [IO.Path]::Combine([Environment]::GetFolderPath('System'), 'WindowsPowerShell\v1.0\Modules')
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $request = [Net.HttpWebRequest]::Create($LauncherUri)
    $request.UseDefaultCredentials = $false
    $request.Timeout = 30000
    $request.ReadWriteTimeout = 30000
    $response = $null; $stream = $null
    $buffer = New-Object IO.MemoryStream
    try {
        $response = $request.GetResponse()
        if ($response.ResponseUri.Scheme -cne 'https' -or $response.ContentLength -gt 16MB) {
            throw 'Launcher response is not bounded HTTPS content.'
        }
        $stream = $response.GetResponseStream()
        $chunk = New-Object byte[] 8192
        while (($count = $stream.Read($chunk, 0, $chunk.Length)) -gt 0) {
            if ($buffer.Length + $count -gt 16MB) { throw 'Launcher exceeds 16 MiB.' }
            $buffer.Write($chunk, 0, $count)
        }
        Invoke-VerifiedQualificationBytes -Bytes $buffer.ToArray() -ExpectedSha256 $ExpectedSha256 -Destination $Destination
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($response) { $response.Dispose() }
        $buffer.Dispose()
    }
}
