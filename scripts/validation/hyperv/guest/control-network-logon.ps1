# CONTROL VM (WinSight-Control-HV), elevated, started by run-guest-checks.ps1 in mode 'control'.
# Kit section 7, "Network Logon", second machine: logs on to the target over WinRM HTTPS with the
# disposable standard account and runs Test-IpcBoundary.ps1 -NetworkLogon there. The operator types
# the disposable password in the Windows credential dialog; it never leaves this VM except inside
# the TLS-protected WinRM logon. Evidence goes to control-results on this VM's data disk, and the
# probe's output is also handed back to the target over the private switch.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$evidence = Join-Path $root 'control-results'
New-Item -ItemType Directory -Force $evidence | Out-Null
Start-Transcript -Path (Join-Path $evidence 'transcript.txt') -Force | Out-Null
$net = Get-Content -LiteralPath (Join-Path $root 'network.json') -Raw | ConvertFrom-Json
$base = "http://$($net.targetAddress):$($net.httpPort)"
$result = [ordered]@{ startedUtc = [DateTime]::UtcNow.ToString('O'); computer = $env:COMPUTERNAME; status = 'NOT_RUN'; detail = '' }
$imported = $null
$clientBasicPath = 'WSMan:\localhost\Client\Auth\Basic'
$previousClientBasic = $null
$winRm = $null
try {
    # The private address, on the adapter the host created with a known MAC. This VM has no other.
    $mac = ($net.controlMac -replace '[-:]', '').ToUpperInvariant()
    $adapter = Get-NetAdapter | Where-Object { ($_.MacAddress -replace '-', '') -eq $mac } | Select-Object -First 1
    if (-not $adapter) { throw "No adapter with MAC $mac." }
    Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $net.controlAddress -PrefixLength $net.prefixLength | Out-Null
    "control address $($net.controlAddress) on $($adapter.Name)"

    # Wait for the target: it serves the rendezvous only once its account, listener and observer exist,
    # which is after the operator has typed the password there.
    $packageRoot = $null
    $deadline = (Get-Date).AddMinutes(60)
    while (-not $packageRoot -and (Get-Date) -lt $deadline) {
        # Windows PowerShell returns a body without a text content type as bytes; decode it. Thirty seconds
        # leave room for proxy auto-detection on a network that has none.
        try { $packageRoot = [Text.Encoding]::UTF8.GetString([byte[]](Invoke-WebRequest -Uri "$base/package-root" -UseBasicParsing -TimeoutSec 30).RawContentStream.ToArray()).Trim() }
        catch { Start-Sleep -Seconds 10 }
    }
    if (-not $packageRoot) { throw 'NOT_RUN: the target never opened its rendezvous (60 minutes).' }
    $certificatePath = Join-Path $evidence 'winrm-network-probe.cer'
    Invoke-WebRequest -Uri "$base/cert" -UseBasicParsing -OutFile $certificatePath
    "target package root: $packageRoot"

    # The kit's control-side commands, client configuration restored in finally.
    $winRm = Get-Service WinRM
    $originalStart = $winRm.StartType
    $originalRunning = $winRm.Status -eq 'Running'
    Set-Service WinRM -StartupType Manual
    Start-Service WinRM
    Import-Module Microsoft.WSMan.Management
    $imported = Import-Certificate -FilePath $certificatePath -CertStoreLocation 'Cert:\LocalMachine\Root'
    $previousClientBasic = [bool](Get-Item -LiteralPath $clientBasicPath).Value
    Set-Item -LiteralPath $clientBasicPath -Value $true -Force

    $credential = Get-Credential -UserName 'WinSightNetworkProbe' -Message 'WinSight gate 36 (CONTROL): type the same disposable password you chose on the target VM.'
    if ($null -eq $credential) { throw 'NOT_RUN: no password was provided on the control VM.' }
    $networkResult = Invoke-Command -ComputerName $net.targetAddress -Credential $credential -UseSSL -Authentication Basic -ScriptBlock {
        param($RemotePackageRoot)
        $scriptPath = Join-Path $RemotePackageRoot 'Test-IpcBoundary.ps1'
        $cliPath = Join-Path $RemotePackageRoot 'winsight.exe'
        $servicePath = Join-Path $RemotePackageRoot 'winsight-firewall-service.exe'
        $nativePowerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $output = @(& $nativePowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
            -File $scriptPath -CliPath $cliPath -ServicePath $servicePath -NetworkLogon *>&1 |
            ForEach-Object { $_.ToString() })
        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    } -ArgumentList $packageRoot
    $networkText = (@($networkResult.Output) + "exit=$($networkResult.ExitCode)") -join [Environment]::NewLine
    $networkText | Set-Content (Join-Path $evidence 'ipc-network-logon.txt')
    $result.status = if ($networkResult.ExitCode -eq 0 -and $networkText -match [regex]::Escape('Result: 7 checks, 0 failure(s).')) { 'PASS' } else { 'FAIL' }
    $result.detail = $networkText
    $networkText
}
catch {
    $result.status = if ($_.Exception.Message -like 'NOT_RUN:*') { 'NOT_RUN' } else { 'FAIL' }
    $result.detail = "$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
    $result.detail
}
finally {
    # Always report, so the target stops waiting and runs its observer and cleanup.
    try { Invoke-WebRequest -Uri "$base/done" -Method Post -UseBasicParsing -TimeoutSec 30 -ContentType 'text/plain; charset=utf-8' `
            -Body ([Text.Encoding]::UTF8.GetBytes([string]$result.detail)) | Out-Null } catch { "could not report to the target: $($_.Exception.Message)" }
    if ($null -ne $previousClientBasic) { Set-Item -LiteralPath $clientBasicPath -Value $previousClientBasic -Force }
    if ($imported) { Remove-Item -LiteralPath ("Cert:\LocalMachine\Root\{0}" -f $imported.Thumbprint) -Force }
    if ($winRm) {
        if (-not $originalRunning) { Stop-Service WinRM -Force -ErrorAction SilentlyContinue }
        Set-Service WinRM -StartupType $originalStart -ErrorAction SilentlyContinue
    }
    $result.finishedUtc = [DateTime]::UtcNow.ToString('O')
    $result | ConvertTo-Json | Set-Content (Join-Path $evidence 'control-result.json') -Encoding UTF8
    Stop-Transcript | Out-Null
}
