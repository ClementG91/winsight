using System.Diagnostics;
using System.Text;
using Xunit;

namespace WinSight.Application.Tests;

public sealed partial class NetworkQualificationLifecycleRegressionTests
{
    [Fact]
    public async Task CampaignLeaseAndDurableActiveStateSurviveARealOwnerProcessDeath()
    {
        var directory = Path.Combine(Path.GetTempPath(), "winsight-transport-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var ready = Path.Combine(directory, "ready");
        var finish = Path.Combine(directory, "finish");
        var root = Path.Combine(directory, "vm-root");
        Directory.CreateDirectory(root);
        var common = """
            $ErrorActionPreference='Stop'
            $module=Import-Module ([IO.Path]::Combine($env:WINSIGHT_LIFECYCLE_HARNESS,'WinSightHyperV.psm1')) -Force -PassThru
            # Only ACL boundaries are isolated: native lease handles, atomic files, JSON, two processes
            # and process termination are real. This cannot attest privileged production DACLs.
            & $module {
                function script:Assert-ProtectedPath {}
                function script:New-ProtectedDirectory($Path) {[void][IO.Directory]::CreateDirectory($Path)}
            }
            $root=$env:WINSIGHT_CAMPAIGN_ROOT
            $contract=[ordered]@{version=1;kind='network';runName='run-a';evidenceRoot='D:\evidence-a';candidateDigest=('a'*64);harnessDigest=('b'*64);timeoutMinutes=5}
            """;
        ProcessStartInfo StartInfo(string body)
        {
            var start = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "Modules");
            start.Environment["WINSIGHT_LIFECYCLE_HARNESS"] = Harness;
            start.Environment["WINSIGHT_CAMPAIGN_ROOT"] = root;
            start.Environment["WINSIGHT_CAMPAIGN_READY"] = ready;
            start.Environment["WINSIGHT_CAMPAIGN_FINISH"] = finish;
            foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(common + "\n" + body)) })
            {
                start.ArgumentList.Add(argument);
            }
            return start;
        }
        Process? owner = null;
        try
        {
            owner = Process.Start(StartInfo("""
                Initialize-WinSightCampaignOwnership -Root $root
                $lease=Enter-WinSightCampaign -Root $root -Contract $contract
                [IO.File]::WriteAllText($env:WINSIGHT_CAMPAIGN_READY+'.tmp',$lease.RunId)
                [IO.File]::Move($env:WINSIGHT_CAMPAIGN_READY+'.tmp',$env:WINSIGHT_CAMPAIGN_READY)
                # Parent bounds readiness and each probe to 30s, then kills only this child.
                # The 90s owner containment outlives those two bounds without racing their proof.
                $deadline=[DateTime]::UtcNow.AddSeconds(90)
                while (-not [IO.File]::Exists($env:WINSIGHT_CAMPAIGN_FINISH) -and [DateTime]::UtcNow -lt $deadline) {[Threading.Thread]::Sleep(25)}
                exit 0
                """))!;
            var stdout = owner.StandardOutput.ReadToEndAsync();
            var stderr = owner.StandardError.ReadToEndAsync();
            var deadline = Stopwatch.StartNew();
            while (!File.Exists(ready) && !owner.HasExited && deadline.Elapsed < TimeSpan.FromSeconds(30))
            {
                await Task.Delay(25);
            }
            Assert.True(File.Exists(ready), "Real lease owner did not become ready: " + (owner.HasExited ? await stderr.WaitAsync(TimeSpan.FromSeconds(5)) : "30-second readiness bound"));
            Assert.False(owner.HasExited, "Lease owner exited before the competing probe.");
            var originalNonce = File.ReadAllText(ready);
            var competing = await PowerShellProcessEvidence.Run(StartInfo("""
                $caught=$false
                try {$unexpected=Enter-WinSightCampaign -Root $root -Contract $contract -Resume;$unexpected.Handle.Dispose()} catch {$caught=$true}
                if (-not $caught) {throw 'ASSERT: a live owner did not exclude the second real process'}
                """), TimeSpan.FromSeconds(30), output.WriteLine);
            Assert.True(competing.ExitCode == 0, competing.Stderr);
            Assert.False(owner.HasExited, "Lease owner exited during the competing probe.");
            // Kill only this test's known child; no process-name matching or other session touched.
            owner.Kill(entireProcessTree: true);
            await owner.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(5));
            var recovered = await PowerShellProcessEvidence.Run(StartInfo("""
                $foreign=[ordered]@{version=1;kind='network';runName='run-b';evidenceRoot='D:\evidence-b';candidateDigest=('a'*64);harnessDigest=('b'*64);timeoutMinutes=5}
                $caught=$false
                try {$unexpected=Enter-WinSightCampaign -Root $root -Contract $foreign;$unexpected.Handle.Dispose()} catch {$caught=$true}
                if (-not $caught) {throw 'ASSERT: process death erased durable active ownership across EvidenceRoots'}
                $lease=Enter-WinSightCampaign -Root $root -Contract $contract -Resume
                if ($lease.RunId -cne [IO.File]::ReadAllText($env:WINSIGHT_CAMPAIGN_READY)) {throw 'ASSERT: Resume invented a new nonce'}
                $seal=[IO.Path]::Combine($root,'synthetic-seal.txt');[IO.File]::WriteAllText($seal,'synthetic sealed and restored receipt')
                Close-WinSightCampaign -Lease $lease -SealPath $seal
                $next=Enter-WinSightCampaign -Root $root -Contract $foreign
                if ($next.RunId -ceq $lease.RunId) {throw 'ASSERT: new campaign reused the closed identity'}
                $next.Handle.Dispose()
                """), TimeSpan.FromSeconds(30), output.WriteLine);
            Assert.True(recovered.ExitCode == 0, recovered.Stderr);
            Assert.True(Guid.TryParse(originalNonce, out _));
        }
        finally
        {
            if (owner is not null)
            {
                if (!owner.HasExited)
                {
                    owner.Kill(entireProcessTree: true);
                    await owner.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
                }
                owner.Dispose();
            }
            var full = Path.GetFullPath(directory);
            Assert.StartsWith(Path.GetFullPath(Path.GetTempPath()), full, StringComparison.OrdinalIgnoreCase);
            Assert.False((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0);
            Directory.Delete(full, recursive: true);
        }
    }
}
