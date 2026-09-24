# Host-provided stand-in for the human operator of the VM qualification. qualify.ps1 dot-sources it,
# elevated, when a gate asks for an operator decision (Request-OperatorAction) or for a tray Exit it
# could not drive itself. It acts only through the real product surface: the dashboard's own buttons,
# the real common file dialog, the real confirmation box, and the tray icon's real context menu.
# Every step is written to operator-automation.txt, so a run that used it is never mistaken for one
# with a human at the console.
param(
    [Parameter(Mandatory)][ValidateSet('ARM', 'ROLLBACK', 'TRAYEXIT')][string]$Name,
    [int]$ProcessId = 0
)

function Write-OperatorLog([string]$Line) {
    "$(Get-Date -Format o) [$Name] $Line" | Add-Content -LiteralPath (Join-Path $Evidence 'operator-automation.txt')
}

function Get-OperatorDashboard {
    if ($ProcessId -gt 0) { return Get-Process -Id $ProcessId -ErrorAction Stop }
    $found = @(Get-Process -Name 'winsight-dashboard' -ErrorAction SilentlyContinue | Sort-Object StartTime -Descending)
    if ($found.Count -eq 0) { throw 'No dashboard process to operate.' }
    return $found[0]
}

# A dialog the dashboard opened: a #32770 window of its process holding the given control. UI
# Automation exposes a dialog owned by a dashboard window under that owner, not at the top level
# (run 8: the file picker was on screen and a top-level-only search never saw it), so both are searched.
function Find-OperatorDialog([int]$OwnerId, [string]$ControlId, [int]$TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $dialogCondition = New-Condition $UIA::ClassNameProperty '#32770'
    $controlCondition = New-Condition $UIA::AutomationIdProperty $ControlId
    do {
        foreach ($window in $UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $OwnerId))) {
            $dialogs = @()
            if ($window.Current.ClassName -eq '#32770') { $dialogs += $window }
            $dialogs += @($window.FindAll($Scope::Descendants, $dialogCondition))
            foreach ($dialog in $dialogs) {
                if ($dialog.FindFirst($Scope::Descendants, $controlCondition)) { return $dialog }
            }
        }
        Start-Sleep -Milliseconds 400
    } while ((Get-Date) -lt $deadline)
    return $null
}

function Invoke-OperatorElement($Element) {
    $Element.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
}

# Types into a dialog the way an operator does: bring it to the front, then send keys to it.
function Send-OperatorKeys($Window, [string]$Keys) {
    Add-Type -AssemblyName System.Windows.Forms
    if (-not ('W.Fg' -as [type])) {
        Add-Type -Name Fg -Namespace W -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool SetForegroundWindow(System.IntPtr h);'
    }
    [void][W.Fg]::SetForegroundWindow([IntPtr]$Window.Current.NativeWindowHandle)
    Start-Sleep -Milliseconds 800
    [System.Windows.Forms.SendKeys]::SendWait($Keys)
    Start-Sleep -Milliseconds 800
}

# The file-name control is 1148, but in the modern dialog that id sits on the combo box and its
# editable part exposed no writable value (runs 9 and 10). UI Automation first, typing as the
# fallback: the picker opens with the file-name box focused, which is how an operator fills it.
function Set-OperatorFileName($Picker, [string]$Path) {
    $candidates = @()
    foreach ($element in @($Picker.FindAll($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty '1148')))) {
        $candidates += $element
        $candidates += @($element.FindAll($Scope::Descendants,
                (New-Condition $UIA::ControlTypeProperty ([System.Windows.Automation.ControlType]::Edit))))
    }
    foreach ($candidate in $candidates) {
        $pattern = $null
        if ($candidate.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern) -and
            -not $pattern.Current.IsReadOnly) {
            $pattern.SetValue($Path)
            Write-OperatorLog "file name set through UI Automation: $Path"
            return
        }
    }
    Send-OperatorKeys $Picker ($Path -replace '([+^%~(){}\[\]])', '{$1}')
    Write-OperatorLog "file name typed into the focused picker: $Path"
}

function Wait-OperatorEnabled($Window, [string]$AutomationId, [int]$TimeoutSeconds = 180) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $element = $Window.FindFirst($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty $AutomationId))
        if ($element -and $element.Current.IsEnabled) { return }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw "'$AutomationId' never became usable."
}

# MessageBox Yes/No. The Yes button is IDYES (6), exposed as "6" by the classic dialog and as
# "CommandButton_6" by the Windows 11 one, and not always as a Button (hv-run1 found a "6" it could
# not invoke, hv-run2 found no Button at all). Invoke it when possible; otherwise press Enter in the
# box, whose default button is Yes.
function Confirm-OperatorYes([int]$OwnerId) {
    $deadline = (Get-Date).AddSeconds(120)
    do {
        foreach ($window in $UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $OwnerId))) {
            $dialogs = @()
            if ($window.Current.ClassName -eq '#32770') { $dialogs += $window }
            $dialogs += @($window.FindAll($Scope::Descendants, (New-Condition $UIA::ClassNameProperty '#32770')))
            foreach ($dialog in $dialogs) {
                $all = @($dialog.FindAll($Scope::Descendants, [System.Windows.Automation.Condition]::TrueCondition))
                $yes = @($all | Where-Object { $_.Current.AutomationId -in '6', 'CommandButton_6' -or $_.Current.Name -match '^&?(Yes|Oui)$' })
                if ($yes.Count -eq 0) { continue }
                foreach ($candidate in $yes) {
                    $pattern = $null
                    if ($candidate.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) {
                        $pattern.Invoke()
                        Write-OperatorLog "confirmation: invoked '$($candidate.Current.Name)' ($($candidate.Current.AutomationId))"
                        return
                    }
                }
                Send-OperatorKeys $dialog '{ENTER}'
                Write-OperatorLog "confirmation: Enter (default Yes); elements seen: $(($all | ForEach-Object { "$($_.Current.ControlType.ProgrammaticName)/$($_.Current.AutomationId)/$($_.Current.Name)" }) -join '; ')"
                return
            }
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    $seen = @($UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $OwnerId)) |
        ForEach-Object { "$($_.Current.ClassName)/$($_.Current.Name)" }) -join '; '
    Write-OperatorLog "no confirmation box; dashboard top-level windows: $seen"
    throw 'The confirmation box did not open.'
}
$operated = Get-OperatorDashboard
switch ($Name) {
    'ARM' {
        $window = Find-ProcessWindowWith $operated.Id 'FirewallBlockAppButton' 60
        if (-not $window) { throw 'The dashboard firewall controls are not on screen.' }
        Invoke-UiButton $window 'FirewallBlockAppButton'
        # Common file dialog: file-name edit 1148, Open button 1. Generous waits: this VM can stall for
        # minutes (run 7 lost 160 s in the middle of this step and its clock then jumped past the wait).
        $picker = Find-OperatorDialog $operated.Id '1148' 90
        $clickedTwice = $false
        if (-not $picker) {
            Write-OperatorLog 'no file picker after the first click; clicking Block an app... once more'
            Invoke-UiButton $window 'FirewallBlockAppButton'
            $clickedTwice = $true
            $picker = Find-OperatorDialog $operated.Id '1148' 180
        }
        if (-not $picker) { throw 'The file picker did not open.' }
        Set-OperatorFileName $picker $CurlExe
        $open = @($picker.FindAll($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty '1')) |
            Where-Object { $_.Current.ControlType -eq [System.Windows.Automation.ControlType]::Button }) | Select-Object -First 1
        if ($open) { Invoke-OperatorElement $open }
        else {
            Send-OperatorKeys $picker '{ENTER}'
            Write-OperatorLog 'Open pressed with Enter (no Open button exposed)'
        }
        $deadline = (Get-Date).AddSeconds(30)
        while ((Find-OperatorDialog $operated.Id '1148' 1) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
        if (Find-OperatorDialog $operated.Id '1148' 1) {
            # Still open: the typed name was not accepted, so say so instead of arming something else.
            Send-OperatorKeys $picker '{ESC}'
            throw 'The file picker did not accept the path.'
        }
        Write-OperatorLog "Block an app... -> $CurlExe -> Open"
        if ($clickedTwice) {
            # Both clicks may have been queued: a second picker opening now is cancelled (button 2).
            $extra = Find-OperatorDialog $operated.Id '1148' 20
            if ($extra) {
                $cancel = @($extra.FindAll($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty '2')) |
                    Where-Object { $_.Current.ControlType -eq [System.Windows.Automation.ControlType]::Button }) | Select-Object -First 1
                if ($cancel) { Invoke-OperatorElement $cancel; Write-OperatorLog 'second queued file picker cancelled' }
            }
        }
        Start-Sleep -Seconds 5
        Invoke-UiButton $window 'ScanButton'
        Start-Sleep -Seconds 12
        Wait-OperatorEnabled $window 'FirewallEnableEnforcementButton'
        Invoke-UiButton $window 'FirewallEnableEnforcementButton'
        Confirm-OperatorYes $operated.Id
        Write-OperatorLog 'Enable enforcement -> Yes'
        Start-Sleep -Seconds 10
    }
    'ROLLBACK' {
        $window = Find-ProcessWindowWith $operated.Id 'FirewallEmergencyButton' 60
        if (-not $window) { throw 'The dashboard firewall controls are not on screen.' }
        Wait-OperatorEnabled $window 'FirewallEmergencyButton'
        Invoke-UiButton $window 'FirewallEmergencyButton'
        Confirm-OperatorYes $operated.Id
        Write-OperatorLog 'Emergency disable -> Yes'
        Start-Sleep -Seconds 10
    }
    'TRAYEXIT' {
        # Explorer reports a click on a notification icon by posting the icon's callback message to its
        # window; WinForms uses WM_USER + 1024 with the mouse message in lParam. Post the right-button-up
        # a real click would produce, then invoke the Exit item of the menu the icon itself opens.
        if (-not ('W.Tray' -as [type])) {
            Add-Type -Name Tray -Namespace W -MemberDefinition @'
public delegate bool EnumProc(System.IntPtr hwnd, System.IntPtr lParam);
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc callback, System.IntPtr lParam);
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(System.IntPtr hwnd, out uint pid);
[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)] public static extern int GetClassName(System.IntPtr hwnd, System.Text.StringBuilder name, int size);
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool PostMessage(System.IntPtr hwnd, uint msg, System.IntPtr wParam, System.IntPtr lParam);
'@
        }
        $targets = New-Object System.Collections.Generic.List[System.IntPtr]
        $callback = [W.Tray+EnumProc] {
            param($hwnd, $unused)
            $owner = [uint32]0
            [void][W.Tray]::GetWindowThreadProcessId($hwnd, [ref]$owner)
            if ($owner -eq $operated.Id) {
                $class = New-Object System.Text.StringBuilder 256
                [void][W.Tray]::GetClassName($hwnd, $class, 256)
                if ($class.ToString() -like 'WindowsForms10.Window*') { $targets.Add($hwnd) }
            }
            return $true
        }
        [void][W.Tray]::EnumWindows($callback, [IntPtr]::Zero)
        foreach ($hwnd in $targets) { [void][W.Tray]::PostMessage($hwnd, 0x0800, [IntPtr]::Zero, [IntPtr]0x0205) }
        Write-OperatorLog "tray callback (right-button-up) posted to $($targets.Count) WinForms window(s)"
        $deadline = (Get-Date).AddSeconds(20)
        $exit = $null
        do {
            foreach ($window in $UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $operated.Id))) {
                $exit = @($window.FindAll($Scope::Descendants, (New-Condition $UIA::NameProperty 'Exit')) |
                    Where-Object { $_.Current.ControlType -eq [System.Windows.Automation.ControlType]::MenuItem }) | Select-Object -First 1
                if ($exit) { break }
            }
            if ($exit) { break }
            Start-Sleep -Milliseconds 500
        } while ((Get-Date) -lt $deadline)
        if (-not $exit) { throw 'The tray context menu did not open.' }
        Invoke-OperatorElement $exit
        Write-OperatorLog 'tray menu -> Exit'
    }
}
