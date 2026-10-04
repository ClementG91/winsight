# Windows PowerShell 5.1. A fresh disposable password, never a personal credential.
# AES key and ciphertext coexist: this is NOT protection against guest/host administrators.
# The boundary is protected offline VM storage and an Administrators/System-only NTFS DACL.
# No fixture is passed in argv, requests, HTTP rendezvous, transcripts or sealed evidence.
Set-StrictMode -Version Latest

function New-NetworkProbeEnvelope {
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new(48)
    $key = [byte[]]::new(32)
    $password = New-Object Security.SecureString
    try {
        $random.GetBytes($bytes)
        $random.GetBytes($key)
        # Guaranteed complexity plus 288 random bits; modulo 64 introduces no bias.
        foreach ($character in 'Aa1!'.ToCharArray()) { $password.AppendChar($character) }
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
        foreach ($value in $bytes) { $password.AppendChar($alphabet[[int]$value -band 63]) }
        $password.MakeReadOnly()
        $cipher = ConvertFrom-SecureString -SecureString $password -Key $key -ErrorAction Stop
        return ([ordered]@{ version = 1; user = 'WinSightNetworkProbe'; key = [Convert]::ToBase64String($key); cipher = $cipher } | ConvertTo-Json -Compress)
    }
    finally { $password.Dispose(); $random.Dispose(); [Array]::Clear($bytes, 0, $bytes.Length); [Array]::Clear($key, 0, $key.Length) }
}

function ConvertFrom-NetworkProbeEnvelope([Parameter(Mandatory)][string]$Envelope) {
    $key = $null
    $password = $null
    try {
        if ($Envelope.Length -gt 4096) { throw 'size' }
        $data = ConvertFrom-Json -InputObject $Envelope -ErrorAction Stop
        $names = @($data.PSObject.Properties.Name | Sort-Object)
        if (($names -join ',') -cne 'cipher,key,user,version' -or $data.version -isnot [int] -or $data.version -ne 1 -or
            $data.user -isnot [string] -or $data.user -cne 'WinSightNetworkProbe' -or
            $data.key -isnot [string] -or $data.cipher -isnot [string]) { throw 'schema' }
        $key = [Convert]::FromBase64String($data.key)
        if ($key.Length -ne 32) { throw 'key' }
        $password = ConvertTo-SecureString -String $data.cipher -Key $key -ErrorAction Stop
        if ($password.Length -ne 52) { throw 'password' }
        $credential = New-Object Management.Automation.PSCredential('WinSightNetworkProbe', $password)
        $password = $null # ownership transferred to the caller, which must dispose it
        return $credential
    }
    catch { throw 'Invalid disposable credential fixture.' }
    finally { if ($password) { $password.Dispose() }; if ($key) { [Array]::Clear($key, 0, $key.Length) } }
}

function New-NetworkProbeAcl([switch]$Directory) {
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') {
        $inheritance = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    return $acl
}

function Assert-NetworkProbePath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unprotected disposable credential path.' }
        $acl = Get-Acl -LiteralPath $current -ErrorAction Stop
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin 'S-1-5-32-544', 'S-1-5-18') { throw 'Unprotected disposable credential path.' }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin 'S-1-5-32-544', 'S-1-5-18') { throw 'Unprotected disposable credential path.' }
        }
        $current = [IO.Path]::GetDirectoryName($current.TrimEnd('\'))
    }
}

# Called ONLY after the trusted host has formatted its fixed offline transport disk.
# Restrict the whole fresh volume before copying anything; parent DELETE_CHILD matters too.
function Set-NetworkProbeVolumeProtection([string]$Root) {
    if ($Root -cnotmatch '^[A-Z]:\\$') { throw 'Expected a fresh transport volume root.' }
    $entries = @([IO.Directory]::GetFileSystemEntries($Root) | Where-Object { [IO.Path]::GetFileName($_) -ne 'System Volume Information' })
    if ($entries.Count) { throw 'Transport volume is not freshly formatted.' }
    [IO.DirectoryInfo]::new($Root).SetAccessControl((New-NetworkProbeAcl -Directory))
    Assert-NetworkProbePath $Root
}

function Write-NetworkProbeFixture([string]$Path, [string]$Envelope) {
    Assert-NetworkProbePath ([IO.Path]::GetDirectoryName($Path))
    $credential = ConvertFrom-NetworkProbeEnvelope $Envelope
    $credential.Password.Dispose()
    $bytes = [Text.Encoding]::UTF8.GetBytes($Envelope)
    $stream = $null
    try {
        $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write,
            [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough, (New-NetworkProbeAcl))
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { if ($stream) { $stream.Dispose() }; [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Remove-NetworkProbeFixture([string]$Path) {
    # Fixed caller-owned filename only. No recursive deletion or reparse traversal.
    if (-not [IO.File]::Exists($Path)) { return }
    Assert-NetworkProbePath $Path
    [IO.File]::Delete($Path)
}

function Receive-NetworkProbeCredential([string]$Path) {
    Assert-NetworkProbePath $Path
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        if ($stream.Length -gt 4096) { throw 'Invalid disposable credential fixture.' }
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true))
        try { return (ConvertFrom-NetworkProbeEnvelope $reader.ReadToEnd()) }
        finally { $reader.Dispose(); $stream = $null }
    }
    catch { throw 'Invalid disposable credential fixture.' }
    finally { if ($stream) { $stream.Dispose() }; Remove-NetworkProbeFixture $Path }
}

Export-ModuleMember -Function New-NetworkProbeEnvelope, ConvertFrom-NetworkProbeEnvelope, Set-NetworkProbeVolumeProtection,
    Write-NetworkProbeFixture, Receive-NetworkProbeCredential, Remove-NetworkProbeFixture
