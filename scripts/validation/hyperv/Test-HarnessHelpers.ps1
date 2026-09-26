# Run UNELEVATED, under Windows PowerShell 5.1 (what the runner uses). Self-checks of the harness
# helpers that need no privilege: the git blob id binding, and the refusals that keep the elevated
# scripts out of links and out of user-owned folders. Prints PASS / FAIL, exits 1 on any FAIL.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WinSightHyperV.psm1') -Force
$repository = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$failures = 0
function Report([bool]$Passed, [string]$Check) {
    $script:failures += [int](-not $Passed)
    '{0} {1}' -f $(if ($Passed) { 'PASS' } else { 'FAIL' }), $Check
}
function Throws([scriptblock]$Block, [string]$Pattern) {
    try { & $Block; return $false } catch { return $_.Exception.Message -match $Pattern }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('winsight-harness-selftest-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $work)
$source = Join-Path $work 'source'
$outside = Join-Path $work 'outside'
$link = Join-Path $source 'link'
try {
    # The blob id computed from the bytes is the one git has for the committed file.
    $tracked = 'LICENSE'
    $expected = (& git -C $repository rev-parse "HEAD:$tracked").Trim()
    $dirty = & git -C $repository status --porcelain -- $tracked
    Report ((-not $dirty) -and (Get-GitBlobId (Join-Path $repository $tracked)) -eq $expected) 'Get-GitBlobId equals git rev-parse HEAD:<path>'

    [void](New-Item -ItemType Directory -Path $source, $outside, (Join-Path $source 'sub'))
    Set-Content -LiteralPath (Join-Path $source 'sub\result.txt') -Value 'guest result'
    Set-Content -LiteralPath (Join-Path $outside 'host-secret.txt') -Value 'must not be collected'
    # A junction needs no privilege: exactly what a guest, or a user, can plant.
    & cmd.exe /c mklink /J "$link" "$outside" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'could not create the test junction' }

    $collected = Join-Path $work 'collected'
    [void](New-Item -ItemType Directory -Path $collected)
    $refused = @(Copy-GuestResults -From $source -To $collected)
    Report ((Test-Path -LiteralPath (Join-Path $collected 'sub\result.txt')) -and
        -not (Test-Path -LiteralPath (Join-Path $collected 'link')) -and
        ($refused -contains 'link (reparse point)')) 'Copy-GuestResults copies files and refuses a junction without entering it'

    Report (Throws { Assert-NoReparseBetween -Root $source -Path (Join-Path $link 'host-secret.txt') } 'Reparse point') 'Assert-NoReparseBetween refuses a junction on the way'
    $staging = Join-Path $work 'staging'
    [void](New-Item -ItemType Directory -Path $staging)
    Report (Throws { Copy-ListedFile -SourceRoot $source -Relative 'link\host-secret.txt' -DestinationRoot $staging } 'Reparse point') 'Copy-ListedFile refuses a file behind a junction'
    Report (Throws { Copy-ListedFile -SourceRoot $source -Relative '..\outside\host-secret.txt' -DestinationRoot $staging } 'Invalid relative path') 'Copy-ListedFile refuses a path that climbs out'
    Copy-ListedFile -SourceRoot $source -Relative 'sub\result.txt' -DestinationRoot $staging
    Report (Test-Path -LiteralPath (Join-Path $staging 'sub\result.txt')) 'Copy-ListedFile copies a listed ordinary file'
    Report (Throws { Assert-ProtectedPath -Path $source } 'Not owned by Administrators|Writable by|renamed|Children of') 'Assert-ProtectedPath refuses a folder an ordinary user owns'
    # The folders above a protected one count: here the user's own profile, which the user can rename.
    Report (Throws { Assert-ProtectedAncestors -Path $source } 'Not owned by Administrators|renamed|Children of') 'Assert-ProtectedAncestors refuses a path under folders an ordinary user controls'
    Report (-not (Throws { Assert-ProtectedAncestors -Path (Join-Path $env:SystemRoot 'System32') } '.')) 'Assert-ProtectedAncestors accepts a path whose parents only administrators can replace'
    # An inheritable entry can hold only the generic bit (GENERIC_ALL), which no specific right matches.
    $generic = [pscustomobject]@{ FileSystemRights = [Enum]::ToObject([System.Security.AccessControl.FileSystemRights], 0x10000000) }
    $module = Get-Module WinSightHyperV
    Report (& $module { param($Rule) Test-Grants $Rule $script:WriteRights } $generic) 'a GENERIC_ALL inheritable entry counts as a write grant'
    Report (Throws { Assert-ProtectedPath -Path $source -Recurse } 'Reparse point|Not owned|Writable by|renamed|Children of') 'Assert-ProtectedPath -Recurse refuses a tree holding a junction'

    # Hyper-V grants its worker process capability on the disks of the VMs it runs. The check trusts
    # that one capability in the VM storage and nowhere else, and still refuses any other.
    $worker = 'S-1-15-3-1024-2268835264-3721307629-241982045-173645152-1490879176-104643441-2915960892-1612460704'
    $trusts = {
        param($Sid, [switch]$VirtualMachines)
        try { [bool](& $module { param($s, $v) Test-TrustedWriter $s -VirtualMachines:$v } $Sid $VirtualMachines.IsPresent) } catch { $null }
    }
    Report ((& $trusts $worker -VirtualMachines) -eq $true -and (& $trusts $worker) -eq $false) 'the Hyper-V worker capability is trusted in the VM storage only'
    Report ((& $trusts 'S-1-15-3-1' -VirtualMachines) -eq $false) 'another capability is not trusted, even in the VM storage'
    Report ((& $trusts 'S-1-5-83-1-1111-2222-3333-4444') -eq $true -and (& $trusts 'S-1-5-11' -VirtualMachines) -eq $false) 'the per-VM identity is trusted, Authenticated Users are not'
    Report ((& $module { $script:VmWorkerProcessCapability }) -eq $worker) 'the module names the vmWorkerProcess capability SID'
    Report ((& $trusts 'S-1-3-0') -eq $true -and (& $trusts 'S-1-3-1' -VirtualMachines) -eq $false) 'CREATOR OWNER is trusted, CREATOR GROUP is not'

    # Every refusal at once, so one run shows all there is to fix.
    $one = Join-Path $work 'refusal-one.bin'
    $two = Join-Path $work 'refusal-two.bin'
    foreach ($file in $one, $two) { [IO.File]::WriteAllText($file, 'x') }
    $listed = try { @(& $module { param($i) Get-ProtectionRefusals -Items $i } ([string[]]@($one, $two))) } catch { @() }
    Report (@($listed | Where-Object { $_ -like '*refusal-one.bin' }).Count -gt 0 -and @($listed | Where-Object { $_ -like '*refusal-two.bin' }).Count -gt 0) 'Assert-ProtectedPath lists every refusal, not only the first'

    # Hyper-V keeps the configuration of its VMs open even while they are off. The seal hashes such a
    # file through every sharing mode, and names one it cannot open at all instead of failing.
    $held = Join-Path $work 'held-open.vmcx'
    [IO.File]::WriteAllText($held, 'configuration')
    $expected = (Get-FileHash -LiteralPath $held -Algorithm SHA256).Hash
    $writer = [IO.File]::Open($held, 'Open', 'ReadWrite', 'Read')
    try { $shared = try { & $module { param($p) Get-SharedFileHash -Path $p } $held } catch { 'threw' } }
    finally { $writer.Dispose() }
    Report ($shared -eq $expected) 'Get-SharedFileHash hashes a file another process holds open for writing'
    $exclusive = [IO.File]::Open($held, 'Open', 'ReadWrite', 'None')
    try { $none = try { $result = & $module { param($p) Get-SharedFileHash -Path $p } $held; if ($null -eq $result) { 'none' } else { $result } } catch { 'threw' } }
    finally { $exclusive.Dispose() }
    Report ($none -eq 'none') 'Get-SharedFileHash answers nothing, without failing, for a file held with no sharing'

    # Restoring a checkpoint gives the VM a new differencing disk owned by the VM's own identity: an
    # owner the storage check accepts in the VM storage, and nowhere else.
    $owns = {
        param($Sid, [switch]$VirtualMachines)
        try { [bool](& $module { param($s, $v) Test-TrustedOwner $s -VirtualMachines:$v } $Sid $VirtualMachines.IsPresent) } catch { $null }
    }
    $vmIdentity = 'S-1-5-83-1-3190545330-1080910426-1459921588-4136893788'
    Report ((& $owns $vmIdentity -VirtualMachines) -eq $true -and (& $owns $vmIdentity) -eq $false -and (& $owns 'S-1-5-11' -VirtualMachines) -eq $false -and (& $owns 'S-1-5-32-544') -eq $true) 'a VM identity may own what is in the VM storage only'

    # The elevated scripts make Administrators the default owner of what they create. Unelevated, the
    # call goes through for the account's own SID and Windows refuses Administrators (1307): it asks
    # for exactly that, and only an elevated token may have it.
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $ownSid = try { & $module { param($s) Set-DefaultOwner -Sid $s } $me; 'set' } catch { $_.Exception.Message }
    $admins = try { & $module { Set-AdministratorsDefaultOwner }; 'set' } catch { $_.Exception.Message }
    Report ($ownSid -eq 'set' -and $admins -match 'Win32 error 1307') 'Set-AdministratorsDefaultOwner asks Windows for Administrators as default owner (refused unelevated)'

    # The network run starts two VMs together: it refuses up front a run the host memory cannot hold.
    Report ((-not (Throws { Assert-WinSightHostMemory -Bytes 1 -Advice 'none' } '.')) -and
        (Throws { Assert-WinSightHostMemory -Bytes 1PB -Advice 'close applications' } 'GB of memory and the host has .* available: close applications')) 'Assert-WinSightHostMemory refuses a run the host memory cannot hold'

    # The Cloud Files gate counts against WinSight the download requests its own processes make, and
    # those the platform cannot attribute. Another program's requests are only recorded.
    $errors = $null
    $probe = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repository 'scripts\Measure-CloudFilesAccess.ps1'), [ref]$null, [ref]$errors)
    $definition = $probe.Find({ param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq 'Get-FetchOwner' }, $true)
    if ($definition) { . ([scriptblock]::Create($definition.Extent.Text)) }
    $owner = { param($ProcessId, $Image, $Ids) try { Get-FetchOwner -ProcessId $ProcessId -Image $Image -WinSightProcessIds $Ids } catch { 'missing' } }
    $volume = '\Device\HarddiskVolume3'
    Report ((& $owner 4242 "$volume\Program Files\WinSight-Qualification\payload\winsight.exe" @()) -eq 'winsight' -and
        (& $owner 4242 "$volume\Program Files\WinSight\WinSight.Dashboard.exe" @()) -eq 'winsight' -and
        (& $owner 4242 "$volume\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe" @(4242)) -eq 'winsight' -and
        (& $owner 4242 "$volume\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe" @(7)) -eq 'other' -and
        (& $owner 4242 'UNKNOWN' @()) -eq 'unattributed' -and (& $owner 4242 '' @()) -eq 'unattributed' -and
        (& $owner 0 "$volume\Windows\explorer.exe" @()) -eq 'unattributed') 'the Cloud Files probe charges WinSight with its own and unattributed download requests only'

    # The probe learns who asked from the CF_CALLBACK_INFO the platform hands its callback. A callback
    # written here at the x64 offsets of cfapi.h must come back as one request from that process. Only
    # the probe's types are compiled: no sync root is registered.
    $decoded = 'not run'
    if ([IntPtr]::Size -eq 8) {
        $decoded = try {
            $addType = $probe.Find({ param($Node) $Node -is [System.Management.Automation.Language.CommandAst] -and $Node.GetCommandName() -eq 'Add-Type' }, $true)
            Add-Type -TypeDefinition $addType.CommandElements[2].Value
            foreach ($name in 'Get-Fetches', 'Format-Fetches') {
                $function = $probe.Find({ param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $name }, $true)
                . ([scriptblock]::Create($function.Extent.Text))
            }
            $marshal = [System.Runtime.InteropServices.Marshal]
            $strings = @($marshal::StringToHGlobalUni("$volume\Program Files\WinSight\winsight.exe"), $marshal::StringToHGlobalUni('winsight persistence --json'), $marshal::StringToHGlobalUni('\Users\probe\dehydrated.exe'))
            $processInfo = $marshal::AllocHGlobal(48)
            $callbackInfo = $marshal::AllocHGlobal(152)
            try {
                foreach ($offset in 0..18) { $marshal::WriteInt64($callbackInfo, $offset * 8, 0) }
                foreach ($offset in 0..5) { $marshal::WriteInt64($processInfo, $offset * 8, 0) }
                $marshal::WriteInt32($processInfo, 0, 48); $marshal::WriteInt32($processInfo, 4, 4242)
                $marshal::WriteIntPtr($processInfo, 8, $strings[0]); $marshal::WriteIntPtr($processInfo, 32, $strings[1])
                $marshal::WriteInt32($callbackInfo, 0, 152); $marshal::WriteIntPtr($callbackInfo, 104, $strings[2]); $marshal::WriteIntPtr($callbackInfo, 136, $processInfo)
                [void][CloudFilesProbe].GetMethod('OnFetch', [Reflection.BindingFlags]'NonPublic, Static').Invoke($null, @($callbackInfo, [IntPtr]::Zero))
            }
            finally { foreach ($pointer in @($strings) + $processInfo + $callbackInfo) { $marshal::FreeHGlobal($pointer) } }
            $request = @(Get-Fetches -From 0 -WinSightProcessIds @())
            if ($request.Count -eq 1 -and $request[0].commandLine -eq 'winsight persistence --json' -and $request[0].file -eq '\Users\probe\dehydrated.exe') { Format-Fetches $request } else { 'wrong request' }
        }
        catch { $_.Exception.Message }
    }
    Report ($decoded -eq 'winsight.exe#4242/winsight') "the Cloud Files probe reads the process that asked from a callback laid out as cfapi.h ($decoded)"

    # Each request is failed at once over the whole file. The failure is built from the connection,
    # transfer and request keys and the file size of the callback, at the x64 offsets of cfapi.h, into
    # CF_OPERATION_INFO (48 bytes) and the TransferData member of CF_OPERATION_PARAMETERS (40 bytes).
    $failure = 'not run'
    if ([IntPtr]::Size -eq 8) {
        $failure = try {
            $marshal = [System.Runtime.InteropServices.Marshal]
            $callbackInfo = $marshal::AllocHGlobal(152)
            try {
                foreach ($offset in 0..18) { $marshal::WriteInt64($callbackInfo, $offset * 8, 0) }
                $marshal::WriteInt32($callbackInfo, 0, 152)
                $marshal::WriteInt64($callbackInfo, 8, 0x1111)
                $marshal::WriteInt64($callbackInfo, 80, 12345)
                $marshal::WriteInt64($callbackInfo, 112, 0x2222)
                $marshal::WriteInt64($callbackInfo, 144, 0x3333)
                $operation = New-Object 'CloudFilesProbe+OperationInfo'
                $transfer = New-Object 'CloudFilesProbe+TransferData'
                [CloudFilesProbe]::DescribeFailure($callbackInfo, [ref]$operation, [ref]$transfer)
            }
            finally { $marshal::FreeHGlobal($callbackInfo) }
            $layout = $marshal::SizeOf([type][CloudFilesProbe+OperationInfo]) -eq 48 -and $marshal::SizeOf([type][CloudFilesProbe+TransferData]) -eq 40 -and
                $marshal::OffsetOf([type][CloudFilesProbe+TransferData], 'Length').ToInt64() -eq 32
            $filled = $operation.StructSize -eq 48 -and $operation.Type -eq 0 -and $operation.ConnectionKey -eq 0x1111 -and $operation.TransferKey -eq 0x2222 -and
                $operation.RequestKey -eq 0x3333 -and $transfer.ParamSize -eq 40 -and $transfer.CompletionStatus -lt 0 -and $transfer.Offset -eq 0 -and $transfer.Length -eq 12345
            if ($layout -and $filled) { 'failed at once over the whole file' } else { "layout $layout, fields $filled" }
        }
        catch { $_.Exception.Message }
    }
    Report ($failure -eq 'failed at once over the whole file') "the Cloud Files probe fails a download request from the keys and size of its callback ($failure)"

    # Someone following the runner's log keeps it open for reading. Add-Content fails then (the
    # control); the harness writers append and rewrite through it.
    $followed = Join-Path $work 'runner.log'
    [IO.File]::WriteAllText($followed, "first`r`n")
    $follower = [IO.File]::Open($followed, 'Open', 'Read', 'ReadWrite')
    try {
        $blocked = try { Add-Content -LiteralPath $followed -Value 'naive' -ErrorAction Stop; $false } catch { $true }
        $shared = try {
            & $module { param($p) Add-SharedLine -Path $p -Line 'second'; Add-SharedLine -Path $p -Line 'third' } $followed
            $appended = [IO.File]::ReadAllText($followed)
            & $module { param($p) Write-SharedText -Path $p -Text '{"status":1}' } $followed
            $appended -eq "first`r`nsecond`r`nthird`r`n" -and [IO.File]::ReadAllText($followed) -eq '{"status":1}'
        }
        catch { $false }
    }
    finally { $follower.Dispose() }
    Report ($blocked -and $shared) 'the harness appends to and rewrites a file another process is reading (Add-Content cannot)'

    # Right after a checkpoint restore, Hyper-V can answer "object not found" for a moment: a query of
    # the restored VM is retried, and gives up with the error once its time is out.
    $counter = @{ tries = 0 }
    $retried = try {
        $value = Invoke-WinSightVmRetry { $counter.tries++; if ($counter.tries -lt 3) { throw 'object not found' }; 'restored' } -Seconds 30
        $gaveUp = try { Invoke-WinSightVmRetry { throw 'still not found' } -Seconds 1; $false } catch { $_.Exception.Message -eq 'still not found' }
        $value -eq 'restored' -and $counter.tries -eq 3 -and $gaveUp
    }
    catch { $false }
    Report $retried 'a query of a restored VM is retried, then fails with its own error'
}
finally {
    # The junction first, by itself: deleting the tree with it in place is how a recursive delete
    # reaches the folder it points to.
    if (Test-Path -LiteralPath $link) { [IO.Directory]::Delete($link, $false) }
    if (Test-Path -LiteralPath (Join-Path $outside 'host-secret.txt')) { } else { $failures++; 'FAIL the junction target was touched' }
    [IO.Directory]::Delete($work, $true)
}
if ($failures -gt 0) { "$failures check(s) failed."; exit 1 }
'All checks passed.'
exit 0
