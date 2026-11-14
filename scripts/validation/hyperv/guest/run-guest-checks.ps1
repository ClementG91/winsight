# GUEST entry point on the Hyper-V data disk (volume WINSIGHTQ). The guest logon task
# WinSightQualificationHyperV runs it elevated after the auto-logon. mode.txt, written by the host
# while the VM is off, says what to do:
#   settle  - first boot on new hardware: wait five minutes, then shut down;
#   qualify - run candidate\qualify.ps1 through a one-shot elevated task (the logon task stops its
#             action after 30 minutes), then shut down so the host knows the run is over;
#   done    - written by the run itself before it shuts down: the run is over, shut down again.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$modeFile = Join-Path $root 'mode.txt'
$mode = Get-Content -LiteralPath $modeFile -ErrorAction SilentlyContinue | Select-Object -First 1

# Tells the host, through the Hyper-V key-value exchange, that the auto-logon happened and this task ran
# for the run whose id the host wrote on this disk. Without it the host cannot tell a guest stuck at its
# logon screen (expired password) from a long run. Best effort: the run itself never depends on it.
function Publish-GuestLogon {
    try {
        $runId = Get-Content -LiteralPath (Join-Path $root 'run-id.txt') -TotalCount 1 -ErrorAction Stop
        if ($runId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return }
        # 'Guest' is the guest-to-host pool (host: GuestExchangeItems). 'Auto' belongs to the integration
        # service itself (intrinsic items): a value written there never reaches the host.
        $pool = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest'
        if (-not (Test-Path -LiteralPath $pool)) { New-Item -Path $pool -Force | Out-Null }
        Set-ItemProperty -LiteralPath $pool -Name 'WinSightQualificationLogon' -Value $runId -Type String
    }
    catch { }
}

switch ($mode) {
    'done' {
        # A VM started again after its run - by anyone - must not run the gates again over results the
        # host has not collected yet (seen in the first full run: every gate ran a second time).
        Stop-Computer -Force
    }
    'settle' {
        Start-Sleep -Seconds 300
        Stop-Computer -Force
    }
    { $_ -in 'qualify', 'control' } {
        # 'control' is the second machine of gate 36 (WinSight-Control-HV): same one-shot visible task,
        # so the operator sees its console and its credential dialog.
        Publish-GuestLogon
        $target = if ($mode -eq 'control') { Join-Path $root 'control-network-logon.ps1' } else { Join-Path $root 'candidate\qualify.ps1' }
        $name = 'WinSightQualificationCandidate'
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
        $command = "& '$target'; Set-Content -LiteralPath '$modeFile' -Value 'done'; Stop-Computer -Force"
        $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
            -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"$command`""
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -RunLevel Highest -LogonType Interactive
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 8)
        Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Force | Out-Null
        Start-ScheduledTask -TaskName $name
    }
}
