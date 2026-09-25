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
