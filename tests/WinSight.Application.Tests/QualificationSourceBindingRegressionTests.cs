using Xunit;

namespace WinSight.Application.Tests;

public sealed partial class NetworkQualificationLifecycleRegressionTests
{
    [Fact]
    public async Task StagingSourceRejectsStaleLengthBeforePublishing()
    {
        await Run(SyntheticTree + """
            $inner=[IO.Path]::Combine($from,'inner');[void][IO.Directory]::CreateDirectory($inner)
            $payload=[IO.Path]::Combine($inner,'payload.bin');[IO.File]::WriteAllBytes($payload,[byte[]](1..32))
            function Get-Item {
                [CmdletBinding()]param([string]$LiteralPath,[switch]$Force)
                if ($LiteralPath -eq $payload) {return [pscustomobject]@{Length=1;PSIsContainer=$false;Attributes=[IO.FileAttributes]::Normal}}
                Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force -ErrorAction Stop
            }
            try {
                $caught=$null;try {Copy-ListedFile -SourceRoot $from -Relative 'inner\payload.bin' -DestinationRoot $to -MaximumBytes 16} catch {$caught=$_}
                if (-not $caught -or $caught.Exception.Message -notmatch 'Too large' -or [IO.Directory]::Exists([IO.Path]::Combine($to,'inner'))) {throw 'ASSERT: staging trusted stale metadata length or created destination before opened-length refusal'}
            }
            finally {Remove-SyntheticTree}
            """);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    public async Task StagingSourceCopiesAcquiredBytesAndReleasesHandles(int length)
    {
        await Run(SyntheticTree + $$"""
            $inner=[IO.Path]::Combine($from,'inner');[void][IO.Directory]::CreateDirectory($inner)
            $payload=[IO.Path]::Combine($inner,'payload.bin');$bytes=[byte[]]::new({{length}});[IO.File]::WriteAllBytes($payload,$bytes)
            $context=$null;$lease=$null
            try {
                Copy-ListedFile -SourceRoot $from -Relative 'inner\payload.bin' -DestinationRoot $to -MaximumBytes 16
                $copied=[IO.File]::ReadAllBytes([IO.Path]::Combine($to,'inner','payload.bin'))
                if ([Convert]::ToBase64String($copied) -cne [Convert]::ToBase64String($bytes)) {throw 'ASSERT: ordinary acquired file was not copied exactly'}
                $context=New-WinSightSourceContext -SourceRoot $from;$lease=$context.OpenFile('inner\payload.bin',16)
                $blocked=$false;try {$writer=[IO.File]::Open($payload,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read);$writer.Dispose()} catch [IO.IOException] {$blocked=$true}
                if (-not $blocked) {throw 'ASSERT: acquired reader allowed a conflicting writer'}
                $blocked=$false;try {[IO.Directory]::Move($inner,$inner+'-moved')} catch [IO.IOException] {$blocked=$true}
                if (-not $blocked) {throw 'ASSERT: file lease did not retain its directory chain'}
                $lease.Dispose();$lease=$null
                [IO.Directory]::Move($inner,$inner+'-moved');[IO.Directory]::Move($inner+'-moved',$inner)
                $blocked=$false;try {[IO.Directory]::Move($from,$from+'-moved')} catch [IO.IOException] {$blocked=$true}
                if (-not $blocked) {throw 'ASSERT: source context did not retain its root'}
                $context.Dispose();$context=$null
                [IO.Directory]::Move($from,$from+'-moved');[IO.Directory]::Move($from+'-moved',$from)
                $writer=[IO.File]::Open($payload,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None);$writer.Dispose()
            }
            finally {if ($lease) {$lease.Dispose()};if ($context) {$context.Dispose()};Remove-SyntheticTree}
            """);
    }

    [Theory]
    [InlineData("../payload.bin")]
    [InlineData("inner/./payload.bin")]
    [InlineData("inner//payload.bin")]
    [InlineData("payload.bin:stream")]
    [InlineData("NUL.exe")]
    [InlineData("inner./payload.bin")]
    [InlineData("payload.bin ")]
    public async Task StagingSourceRejectsAmbiguousRelativePathsBeforeDestination(string relative)
    {
        await Run(SyntheticTree + $$"""
            try {
                $caught=$null;try {Copy-ListedFile -SourceRoot $from -Relative '{{relative}}' -DestinationRoot $to} catch {$caught=$_}
                if (-not $caught -or $caught.Exception.Message -notmatch 'Invalid relative path' -or [IO.Directory]::GetFileSystemEntries($to).Length -ne 0) {throw 'ASSERT: ambiguous source path reached destination staging'}
            }
            finally {Remove-SyntheticTree}
            """);
    }

    [Theory]
    [InlineData("D:relative")]
    [InlineData("\\\\127.0.0.1\\WinSight-test-absent\\source")]
    [InlineData("\\\\?\\D:\\source")]
    public async Task StagingSourceRejectsNonordinarySourceRoots(string sourceRoot)
    {
        await Run(SyntheticTree + $$"""
            try {
                $caught=$null;try {Copy-ListedFile -SourceRoot '{{sourceRoot}}' -Relative 'payload.bin' -DestinationRoot $to} catch {$caught=$_}
                if (-not $caught -or $caught.Exception.Message -notmatch 'local drive' -or [IO.Directory]::GetFileSystemEntries($to).Length -ne 0) {throw 'ASSERT: nonordinary source root was not rejected lexically'}
            }
            finally {Remove-SyntheticTree}
            """);
    }

    [Fact]
    public async Task StagingSourceRefusesHardlinksAndReparseAncestors()
    {
        await Run(SyntheticTree + """
            $payload=[IO.Path]::Combine($from,'payload.bin');[IO.File]::WriteAllText($payload,'owned-fixture')
            $alias=[IO.Path]::Combine($from,'alias.bin');$link=[IO.Path]::Combine($from,'nested')
            try {
                New-Item -ItemType HardLink -Path $alias -Value $payload|Out-Null
                $caught=$null;try {Copy-ListedFile -SourceRoot $from -Relative 'alias.bin' -DestinationRoot $to} catch {$caught=$_}
                if (-not $caught -or $caught.Exception.Message -notmatch 'hard.?link') {throw 'ASSERT: staging accepted a multiply linked source'}
                [IO.File]::Delete($alias)
                New-Item -ItemType Junction -Path $link -Value $to|Out-Null
                $caught=$null;try {Copy-ListedFile -SourceRoot $from -Relative 'nested\payload.bin' -DestinationRoot $to} catch {$caught=$_}
                if (-not $caught -or $caught.Exception.Message -notmatch 'Reparse point') {throw 'ASSERT: staging accepted a reparse ancestor or failed for another reason'}
                if ([IO.Directory]::GetFileSystemEntries($to).Length -ne 0 -or [IO.File]::ReadAllText($payload) -cne 'owned-fixture') {throw 'ASSERT: refused alias altered fixture or destination'}
            }
            finally {if ([IO.Directory]::Exists($link)) {[IO.Directory]::Delete($link)};Remove-SyntheticTree}
            """);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StagingSourceActualStageUsesCapturedMetadataAndIgnoresUnlistedEntries(bool bom)
    {
        await Run(SyntheticTree + SourceStageSetup + $$"""
            $encoding=[Text.UTF8Encoding]::new(${{bom.ToString().ToLowerInvariant()}})
            [byte[]]$original=$encoding.GetPreamble()+$encoding.GetBytes(($inventory|ConvertTo-Json -Depth 6))
            [IO.File]::WriteAllBytes($metadata,$original)
            foreach ($n in 1..2002) {[void][IO.Directory]::CreateDirectory([IO.Path]::Combine($source,'ignored-'+$n))}
            $script:originalCopy=(Get-Command Copy-ListedFile).ScriptBlock;$script:mutations=0
            function Copy-ListedFile {
                param($SourceRoot,$Relative,$DestinationRoot,[int64]$MaximumBytes=2GB,$SourceContext)
                if ($script:mutations++ -eq 0) {[IO.File]::WriteAllText($metadata,'{"changed":"after inventory capture"}')}
                & $script:originalCopy @PSBoundParameters
            }
            try {
                $id=Invoke-Stage ([pscustomobject]@{candidate='sample'})
                $staged=[IO.Path]::Combine($Root,'candidates',$id)
                if ($status.candidate -cne $id -or $script:mutations -lt 1) {throw 'ASSERT: actual stage did not publish validated inventory'}
                if ([Convert]::ToBase64String([IO.File]::ReadAllBytes([IO.Path]::Combine($staged,'candidate.json'))) -cne [Convert]::ToBase64String($original)) {throw 'ASSERT: metadata was reread or its captured bytes were normalized'}
                if ([IO.File]::ReadAllText($metadata) -cne '{"changed":"after inventory capture"}') {throw 'ASSERT: metadata change control was not exercised'}
                if ((Get-FileHash -LiteralPath ([IO.Path]::Combine($staged,$artifact)) -Algorithm SHA256).Hash -ne $inventory.artifacts[$artifact]) {throw 'ASSERT: staged artifact bytes are not inventory-bound'}
                if ([IO.Directory]::GetDirectories($staged).Length -ne 1 -or -not [IO.File]::Exists([IO.Path]::Combine($staged,'source','scripts','probe.ps1'))) {throw 'ASSERT: unlisted directories staged or listed source omitted'}
                [IO.Directory]::Move($source,$source+'-released');[IO.Directory]::Move($source+'-released',$source)
            }
            finally {Remove-SyntheticTree}
            """, driverFile: "WinSightQualRunner.ps1");
    }

    [Theory]
    [InlineData("hash")]
    [InlineData("alias")]
    [InlineData("duplicate")]
    [InlineData("utf8")]
    public async Task StagingSourceFailedInventoryCannotReplaceThePublishedPointer(string failure)
    {
        await Run(SyntheticTree + SourceStageSetup + $$"""
            if ('{{failure}}' -ceq 'hash') {$inventory.artifacts[$artifact]=('0'*64)}
            if ('{{failure}}' -ceq 'alias') {$inventory.source['scripts/probe.ps1']=$inventory.source['scripts\probe.ps1']}
            $json=$inventory|ConvertTo-Json -Depth 6
            if ('{{failure}}' -ceq 'duplicate') {$escaped='"arti\u0066acts":'+($inventory.artifacts|ConvertTo-Json -Compress);$json=$json.Insert($json.IndexOf('{')+1,$escaped+',')}
            [IO.File]::WriteAllText($metadata,$json,[Text.UTF8Encoding]::new($false))
            if ('{{failure}}' -ceq 'utf8') {[IO.File]::WriteAllBytes($metadata,[byte[]]@(255))}
            $script:originalCopy=(Get-Command Copy-ListedFile).ScriptBlock;$script:copyCalls=0
            function Copy-ListedFile {
                param($SourceRoot,$Relative,$DestinationRoot,[int64]$MaximumBytes=2GB,$SourceContext)
                $script:copyCalls++;& $script:originalCopy @PSBoundParameters
            }
            try {
                $caught=$null;try {Invoke-Stage ([pscustomobject]@{candidate='sample'})|Out-Null} catch {$caught=$_}
                if (-not $caught -or $status.candidate -cne 'previous-pointer' -or $null -ne $script:candidateManifest) {throw 'ASSERT: invalid inventory published or replaced a previous candidate pointer'}
                if ('{{failure}}' -ceq 'hash' -and $caught.Exception.Message -notmatch 'hash mismatch') {throw 'ASSERT: hash mismatch refused for unrelated reason'}
                if ('{{failure}}' -in 'alias','duplicate' -and ($caught.Exception.Message -notmatch '(duplicate|collision)' -or $script:copyCalls -ne 0)) {throw 'ASSERT: ambiguous inventory was not refused before copying for its duplicate identity'}
                if ('{{failure}}' -ceq 'utf8' -and ($caught.Exception.GetBaseException() -isnot [Text.DecoderFallbackException] -or $script:copyCalls -ne 0)) {throw 'ASSERT: invalid UTF8 was not refused by strict decoding before copying'}
                [IO.Directory]::Move($source,$source+'-released');[IO.Directory]::Move($source+'-released',$source)
            }
            finally {Remove-SyntheticTree}
            """, driverFile: "WinSightQualRunner.ps1");
    }

    [Theory]
    [InlineData("entry")]
    [InlineData("depth")]
    public async Task StagingSourceAcceptsInventoryAtTheExplicitBound(string kind)
    {
        await Run(SyntheticTree + $$"""
            $inventory=[ordered]@{artifacts=[ordered]@{};source=[ordered]@{ } }
            if ('{{kind}}' -ceq 'entry') {foreach ($n in 1..399) {$inventory.artifacts['winsight-v1.0.'+$n+'-win-x64.zip']=('a'*64)} }
            else {$inventory.artifacts['winsight-v1.0.0-win-x64.zip']=('a'*64);$inventory.source['scripts\'+('d\'*13)+'probe.ps1']=('a'*64)}
            [IO.File]::WriteAllText([IO.Path]::Combine($from,'candidate.json'),($inventory|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
            try {
                $captured=Get-BoundedStagingFiles -SourceRoot $from
                $expected=if ('{{kind}}' -ceq 'entry') {399} else {2}
                if ($captured.Files.Count -ne $expected -or $captured.Bytes.Length -eq 0) {throw 'ASSERT: inventory exactly at the explicit bound was rejected or truncated'}
            }
            finally {Remove-SyntheticTree}
            """, driverFile: "WinSightQualRunner.ps1");
    }

    [Fact]
    public async Task StagingSourceRejectsOversizedMetadataBeforePublication()
    {
        await Run(SyntheticTree + SourceStageSetup + """
            [IO.File]::WriteAllBytes($metadata,[byte[]]::new(1MB+1))
            try {
                $caught=$null;try {Invoke-Stage ([pscustomobject]@{candidate='sample'})|Out-Null} catch {$caught=$_}
                if (-not $caught -or $caught.Exception.Message -notmatch 'Too large' -or $status.candidate -cne 'previous-pointer' -or [IO.Directory]::Exists([IO.Path]::Combine($Root,'candidates'))) {throw 'ASSERT: oversized metadata reached destination or publication'}
            }
            finally {Remove-SyntheticTree}
            """, driverFile: "WinSightQualRunner.ps1");
    }

    [Fact]
    public async Task StagingSourceAggregateBudgetRefusesTheLastFileWithoutPublishing()
    {
        await Run(SyntheticTree + SourceStageSetup + """
            [IO.File]::WriteAllText($metadata,($inventory|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
            $stage=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-Stage'},$true)
            $parameters=if ($stage.Parameters.Count -gt 0) {$stage.Parameters} else {$stage.Body.ParamBlock.Parameters}
            $default=$parameters|Where-Object {$_.Name.VariablePath.UserPath -ceq 'MaximumTotalBytes'}
            if (-not $default -or $default.DefaultValue.SafeGetValue() -ne 4GB) {throw 'ASSERT: production aggregate staging default is not4GiB'}
            $budget=[IO.FileInfo]::new($metadata).Length+[IO.FileInfo]::new([IO.Path]::Combine($source,$artifact)).Length+[IO.FileInfo]::new([IO.Path]::Combine($source,'source','scripts','probe.ps1')).Length-1
            try {
                $caught=$null;try {Invoke-Stage ([pscustomobject]@{candidate='sample'}) -MaximumTotalBytes $budget|Out-Null} catch {$caught=$_}
                if (-not $caught -or $caught.Exception.Message -notmatch '(Too large|byte limit)' -or $status.candidate -cne 'previous-pointer' -or $null -ne $script:candidateManifest) {throw 'ASSERT: aggregate acquired-byte budget did not preserve prior pointer'}
            }
            finally {Remove-SyntheticTree}
            """, driverFile: "WinSightQualRunner.ps1");
    }

    private const string SourceStageSetup = """
        $Requests=[IO.Path]::Combine($work,'requests');$source=[IO.Path]::Combine($Requests,'candidates','sample')
        [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($source,'source','scripts'))
        $Root=$to;$VmRoot='boundary-mock';$stamp='synthetic';$sealed=[IO.Path]::Combine($Root,'sealed');[void][IO.Directory]::CreateDirectory($sealed)
        $status=[ordered]@{candidate='previous-pointer'};$script:candidateManifest=$null
        function Get-WinSightCampaignContext {return [pscustomobject]@{Handle=[IO.MemoryStream]::new()}}
        function New-ProtectedDirectory($Path) {[void][IO.Directory]::CreateDirectory($Path)}
        function Assert-ProtectedPath {}
        $artifact='winsight-v0.14.2-win-x64-setup.exe'
        [IO.File]::WriteAllText([IO.Path]::Combine($source,$artifact),'inert-setup-fixture')
        [IO.File]::WriteAllText([IO.Path]::Combine($source,'source','scripts','probe.ps1'),'# inert source fixture; never executed')
        $inventory=[ordered]@{version='0.14.2';commit=('a'*40);artifacts=[ordered]@{};source=[ordered]@{}}
        $inventory.artifacts[$artifact]=(Get-FileHash -LiteralPath ([IO.Path]::Combine($source,$artifact)) -Algorithm SHA256).Hash
        $inventory.source['scripts\probe.ps1']=(Get-FileHash -LiteralPath ([IO.Path]::Combine($source,'source','scripts','probe.ps1')) -Algorithm SHA256).Hash
        $metadata=[IO.Path]::Combine($source,'candidate.json');
        """;
}
