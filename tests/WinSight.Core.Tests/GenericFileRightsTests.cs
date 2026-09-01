using System.Security.AccessControl;

using WinSight.Core;
using Xunit;

namespace WinSight.Core.Tests;

/// <summary>
/// Generic access bits, expanded into the specific rights Windows resolves them to.
/// </summary>
/// <remarks>
/// <b>What was wrong.</b> Two checks tested specific rights against a mask read straight out of a
/// DACL, and .NET returns that mask exactly as stored - it does not apply the object's generic
/// mapping. An ACE granting <c>GENERIC_ALL</c> is <c>0x10000000</c> and shares no bit with
/// <see cref="FileSystemRights.WriteData"/>, <see cref="FileSystemRights.Delete"/> or anything else
/// those checks looked for, so both answered "nothing dangerous here":
///
/// the privileged service trusted a policy path an unprivileged account fully controls, and the
/// hijack scan reported a plantable directory as safe. Both failed in the direction that matters,
/// and an attacker who can set an ACL at all can choose the spelling - <c>icacls /grant Users:(F)</c>
/// and an SDDL <c>GA</c> both produce it.
/// </remarks>
public sealed class GenericFileRightsTests
{
    private const FileSystemRights GenericAll = (FileSystemRights)0x10000000;
    private const FileSystemRights GenericExecute = (FileSystemRights)0x20000000;
    private const FileSystemRights GenericWrite = (FileSystemRights)0x40000000;
    private const FileSystemRights GenericRead = unchecked((FileSystemRights)(int)0x80000000);

    /// <summary>
    /// The case that broke the service's path-trust check: full control, spelled generically.
    /// </summary>
    [Fact]
    public void GenericAllGrantsEveryRightThatMattersToAWritabilityCheck()
    {
        var expanded = GenericFileRights.Expand(GenericAll);

        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.WriteData);
        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.AppendData);
        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.Delete);
        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.DeleteSubdirectoriesAndFiles);
        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.ChangePermissions);
        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.TakeOwnership);
    }

    /// <summary>
    /// The case that broke the hijack scan: the right to plant a file, spelled generically.
    /// </summary>
    [Fact]
    public void GenericWriteGrantsTheRightToPlantAFile()
    {
        var expanded = GenericFileRights.Expand(GenericWrite);

        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.WriteData);
        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.AppendData);
        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.Write);
    }

    /// <summary>
    /// Expansion must not invent write access. A read-only or execute-only generic grant stays
    /// harmless, or the fix would turn every readable directory into a finding.
    /// </summary>
    [Theory]
    [InlineData(0x80000000u)]
    [InlineData(0x20000000u)]
    public void AReadOrExecuteGrantConfersNoWriteAccess(uint generic)
    {
        var expanded = GenericFileRights.Expand(unchecked((FileSystemRights)(int)generic));

        Assert.Equal((FileSystemRights)0, expanded & FileSystemRights.WriteData);
        Assert.Equal((FileSystemRights)0, expanded & FileSystemRights.AppendData);
        Assert.Equal((FileSystemRights)0, expanded & FileSystemRights.Delete);
        Assert.Equal((FileSystemRights)0, expanded & FileSystemRights.ChangePermissions);
        Assert.Equal((FileSystemRights)0, expanded & FileSystemRights.TakeOwnership);
    }

    [Fact]
    public void GenericReadGrantsTheReadRights()
    {
        var expanded = GenericFileRights.Expand(GenericRead);

        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.ReadData);
        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.ReadAttributes);
        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.ReadPermissions);
    }

    [Fact]
    public void GenericExecuteGrantsExecute() =>
        Assert.NotEqual(
            (FileSystemRights)0,
            GenericFileRights.Expand(GenericExecute) & FileSystemRights.ExecuteFile);

    /// <summary>
    /// A mask with no generic bit is returned untouched. The expansion must be invisible to the
    /// overwhelming majority of ACEs, which are already specific.
    /// </summary>
    [Theory]
    [InlineData(FileSystemRights.ReadAndExecute)]
    [InlineData(FileSystemRights.Modify)]
    [InlineData(FileSystemRights.FullControl)]
    [InlineData(FileSystemRights.WriteData)]
    [InlineData((FileSystemRights)0)]
    public void ASpecificMaskIsUnchanged(FileSystemRights rights) =>
        Assert.Equal(rights, GenericFileRights.Expand(rights));

    /// <summary>
    /// The generic bits are cleared once expanded. Leaving them set invites a later mask comparison
    /// that succeeds for the wrong reason.
    /// </summary>
    [Fact]
    public void TheGenericBitsThemselvesAreCleared()
    {
        var expanded = (int)GenericFileRights.Expand(GenericAll | GenericWrite);

        Assert.Equal(0, expanded & unchecked((int)0xF0000000));
    }

    /// <summary>
    /// Combined spellings accumulate rather than one overwriting the other: real descriptors carry
    /// specific and generic bits in the same ACE.
    /// </summary>
    [Fact]
    public void SpecificAndGenericBitsInOneMaskAreBothHonoured()
    {
        var expanded = GenericFileRights.Expand(FileSystemRights.Delete | GenericWrite);

        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.Delete);
        Assert.NotEqual((FileSystemRights)0, expanded & FileSystemRights.WriteData);
    }
}
