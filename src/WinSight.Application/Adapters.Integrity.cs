using WinSight.CodeIntegrity;
using WinSight.Ransomware;
using WinSight.Reporting;

namespace WinSight.Application;

public static partial class Adapters
{
    /// <summary>
    /// What this machine currently enforces about the code it will run, and about its own boot
    /// chain: driver signing, test signing, memory integrity, Secure Boot, kernel debugger.
    /// </summary>
    /// <remarks>
    /// This is the scan that gives the others their meaning. "An unsigned kernel driver is
    /// registered" reads very differently on a machine in test signing, where loading unsigned
    /// drivers is the documented consequence of a setting rather than an anomaly. It is small and
    /// cheap, so it belongs in the balanced overview despite being only a handful of lines.
    ///
    /// It also carries Microsoft Defender's <b>Controlled Folder Access</b> posture, for the same
    /// reason: it is the same genre of "is this Windows self-protection actually switched on", and it
    /// is the one place WinSight can point at the kernel-level BLOCK that its own user-mode ransomware
    /// decoys deliberately cannot perform. WinSight only reads and reports the setting; it never
    /// changes it — the operator flips it in Windows Security via the deep link on the finding.
    /// </remarks>
    public static ToolReport CodeIntegrity(bool flaggedOnly) =>
        CodeIntegrity(flaggedOnly, CancellationToken.None);

    /// <summary>Runs the integrity report while propagating cancellation into every provider read.</summary>
    public static ToolReport CodeIntegrity(bool flaggedOnly, CancellationToken cancellationToken) =>
        CodeIntegrity(
            flaggedOnly,
            new ControlledFolderAccessReader(),
            new SecurityCenterReader(),
            cancellationToken);

    /// <summary>
    /// Composes the code-integrity report with already-created readers. Internal so tests can exercise
    /// report composition without consulting the host's Defender provider or Security Center.
    /// </summary>
    /// <remarks>
    /// Both readers are required, deliberately. An earlier version defaulted the Security Center
    /// reader to null and constructed a real one when it was, which silently voided the
    /// host-independence this seam exists to provide: composition tests kept passing on a developer
    /// machine and failed on Windows Server, which does not ship Security Center at all. A seam that
    /// quietly falls back to the host is worse than no seam, because it looks injected.
    /// </remarks>
    internal static ToolReport CodeIntegrity(
        bool flaggedOnly,
        ControlledFolderAccessReader controlledFolderAccessReader,
        SecurityCenterReader securityCenterReader,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(controlledFolderAccessReader);
        ArgumentNullException.ThrowIfNull(securityCenterReader);
        cancellationToken.ThrowIfCancellationRequested();
        var findings = CodeIntegrityTriage.Evaluate(new CodeIntegrityReader().Read());
        cancellationToken.ThrowIfCancellationRequested();
        var b = new ToolReport.Builder("integrity");
        var checkedCount = 0;
        var notable = 0;
        var unavailable = 0;
        foreach (var finding in findings)
        {
            checkedCount++;
            var isNotable = CodeIntegrityTriage.IsNotable(finding.Concern);
            if (isNotable)
            {
                notable++;
            }
            if (flaggedOnly && !isNotable)
            {
                continue;
            }
            b.Add(
                isNotable ? Severity.Notable
                    // A protection whose state the kernel would not report is the same kind of thing
                    // as an autostart entry whose target is not on disk: nothing is known either way.
                    : finding.Concern is IntegrityConcern.Unreadable ? Severity.Unverified
                    : Severity.Info,
                finding.Name,
                finding.Detail,
                new Dictionary<string, string?>
                {
                    ["protection"] = finding.Name,
                    ["concern"] = finding.Concern.ToString(),
                    // The sub-case, not just the verdict. HVCI is a hardening gap both when it is off
                    // and when it is in audit mode, and those are not the same sentence - the
                    // dashboard needs the distinction to say either of them in French.
                    ["state"] = finding.State,
                });
        }

        // What Windows Security Center says is actually protecting this machine. Read before the CFA
        // posture because the CFA verdict is only honest in its light: "the ransomware shield is not
        // protecting you" is an accurate sentence that leaves a false impression on a machine whose
        // antivirus is Norton and is working fine.
        var inventory = securityCenterReader.Read(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var antivirusConcern = SecurityProductTriage.Concern(inventory);
        var antivirusNotable = SecurityProductTriage.IsNotable(antivirusConcern);
        if (inventory.Reading == SecurityCenterReading.Unavailable)
        {
            unavailable++;
        }
        else
        {
            checkedCount++;
        }
        if (antivirusNotable)
        {
            notable++;
        }
        if (!flaggedOnly || antivirusNotable)
        {
            b.Add(
                antivirusNotable ? Severity.Notable : Severity.Info,
                "Antivirus protection (Windows Security Center)",
                DescribeAntivirus(inventory, antivirusConcern),
                AntivirusFields(inventory, antivirusConcern));
        }

        cancellationToken.ThrowIfCancellationRequested();
        var shield = controlledFolderAccessReader.Read(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (shield.State == ControlledFolderAccessState.Unavailable)
        {
            unavailable++;
        }
        else
        {
            checkedCount++;
        }
        if (shield.IsNotable)
        {
            notable++;
        }
        if (!flaggedOnly || shield.IsNotable)
        {
            b.Add(
                shield.IsNotable ? Severity.Notable : Severity.Info,
                "Controlled Folder Access (ransomware shield)",
                DescribeShield(shield, inventory),
                ControlledFolderAccessFields(shield, inventory, antivirusConcern));
        }

        return b.Build(
            $"{checkedCount} protection(s) checked, {notable} requiring attention, {unavailable} unavailable");
    }

    /// <summary>
    /// Plain-language line for a Controlled Folder Access posture. Names the concrete gap and, when
    /// there is one, the Windows Security deep link the operator uses to close it themselves.
    /// </summary>
    /// <summary>Comma-joined registered names, or null when there are none to name.</summary>
    private static string? NamesOf(IReadOnlyList<SecurityProduct> products) =>
        products.Count == 0 ? null : string.Join(", ", products.Select(product => product.DisplayName));

    private static string CountAntivirusState(
        SecurityProductInventory inventory,
        SecurityProductState state) =>
        inventory.AntiVirusProducts.Count(product => product.State == state)
            .ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static Dictionary<string, string?> AntivirusFields(
        SecurityProductInventory inventory,
        AntiVirusConcern concern)
    {
        var products = inventory.AntiVirusProducts;
        var fields = new Dictionary<string, string?>
        {
            ["protection"] = "Antivirus",
            ["concern"] = concern.ToString(),
            ["reading"] = inventory.Reading.ToString(),
            ["registeredAntivirus"] = NamesOf(products),
            // Legacy aliases retained for existing JSON consumers. Canonical structured state uses
            // antivirusProduct.<index>.* and the Windows vocabulary On/Off/Snoozed/Expired/Unknown.
            ["activeAntivirus"] = NamesOf(inventory.ActiveAntiVirusProducts),
            ["activeAntivirusCount"] = Invariant(inventory.ActiveAntiVirusProducts.Count),
            ["onAntivirus"] = NamesOf(inventory.ActiveAntiVirusProducts),
            ["onAntivirusCount"] = Invariant(inventory.ActiveAntiVirusProducts.Count),
            ["registeredAntivirusCount"] = Invariant(products.Count),
            ["offAntivirusCount"] = CountAntivirusState(inventory, SecurityProductState.Disabled),
            ["snoozedAntivirusCount"] = CountAntivirusState(inventory, SecurityProductState.Snoozed),
            ["expiredAntivirusCount"] = CountAntivirusState(inventory, SecurityProductState.Expired),
            ["activityUnknownAntivirusCount"] = CountAntivirusState(inventory, SecurityProductState.Unknown),
            ["signatureUnknownAntivirusCount"] = Invariant(products.Count(product =>
                product.Signatures == SecurityProductSignatures.Unknown)),
            ["hasActiveNonMicrosoftAntivirus"] = inventory.HasActiveNonMicrosoftAntiVirus.ToString(),
        };

        for (var index = 0; index < products.Count; index++)
        {
            var product = products[index];
            var prefix = $"antivirusProduct.{index}.";
            fields[$"{prefix}name"] = product.DisplayName;
            fields[$"{prefix}activity"] = ProductActivity(product.State);
            fields[$"{prefix}signature"] = ProductSignature(product.Signatures);
            fields[$"{prefix}rawActivity"] = product.RawActivityState?.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
            fields[$"{prefix}rawSignature"] = product.RawSignatureStatus?.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
            fields[$"{prefix}legacyRawProductState"] = product.RawProductState.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
        }

        return fields;
    }

    private static Dictionary<string, string?> ControlledFolderAccessFields(
        ControlledFolderAccessPosture shield,
        SecurityProductInventory inventory,
        AntiVirusConcern antivirusConcern) => new()
        {
            ["protection"] = "Controlled Folder Access",
            ["state"] = shield.State.ToString(),
            ["rawStateValue"] = shield.RawStateValue?.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["concern"] = shield.Concern.ToString(),
            ["runtimeSupportsProtection"] = shield.RuntimeSupportsProtection.ToString(),
            ["amRunningMode"] = shield.RuntimeEvidence.AMRunningMode,
            ["antivirusEnabled"] = shield.RuntimeEvidence.AntivirusEnabled?.ToString(),
            ["realTimeProtectionEnabled"] = shield.RuntimeEvidence.RealTimeProtectionEnabled?.ToString(),
            ["protectedFolders"] = Invariant(shield.ProtectedFolders.Count),
            ["allowedApplicationsVisibility"] = shield.AllowedApplications.Visibility.ToString(),
            ["settingsDeepLink"] = ControlledFolderAccessReader.SettingsDeepLink,
            ["securityCenterReading"] = inventory.Reading.ToString(),
            ["antivirusConcern"] = antivirusConcern.ToString(),
            ["protectedThirdPartyAntivirus"] = NamesOf(ProtectedThirdPartyProducts(inventory)),
            ["onThirdPartyAntivirus"] = NamesOf(OnThirdPartyProducts(inventory)),
            ["onAntivirus"] = NamesOf(inventory.ActiveAntiVirusProducts),
            ["activityUnknownAntivirus"] = NamesOf(
            [.. inventory.AntiVirusProducts.Where(product =>
                product.State == SecurityProductState.Unknown)]),
        };

    private static IReadOnlyList<SecurityProduct> ProtectedThirdPartyProducts(
        SecurityProductInventory inventory) =>
        [.. inventory.ActiveAntiVirusProducts.Where(product =>
            !product.IsMicrosoftDefender
            && product.Signatures == SecurityProductSignatures.UpToDate)];

    private static IReadOnlyList<SecurityProduct> OnThirdPartyProducts(
        SecurityProductInventory inventory) =>
        [.. inventory.ActiveAntiVirusProducts.Where(product => !product.IsMicrosoftDefender)];

    private static string Invariant(int value) =>
        value.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static string ProductActivity(SecurityProductState state) => state switch
    {
        SecurityProductState.Enabled => "On",
        SecurityProductState.Disabled => "Off",
        SecurityProductState.Snoozed => "Snoozed",
        SecurityProductState.Expired => "Expired",
        _ => "Unknown",
    };

    private static string ProductSignature(SecurityProductSignatures signatures) => signatures switch
    {
        SecurityProductSignatures.UpToDate => "UpToDate",
        SecurityProductSignatures.OutOfDate => "OutOfDate",
        _ => "Unknown",
    };

    private static string ExplicitlyInactiveStates(SecurityProductInventory inventory) =>
        string.Join(
            "; ",
            new[]
            {
                (Label: "Off", State: SecurityProductState.Disabled),
                (Label: "Snoozed", State: SecurityProductState.Snoozed),
                (Label: "Expired", State: SecurityProductState.Expired),
            }
            .Select(group =>
            {
                var products = inventory.AntiVirusProducts
                    .Where(product => product.State == group.State)
                    .ToArray();
                return products.Length == 0 ? null : $"{group.Label}: {NamesOf(products)}";
            })
            .Where(description => description is not null)!);

    /// <summary>
    /// Plain-language line for what Windows Security Center reports is protecting this machine.
    /// </summary>
    private static string DescribeAntivirus(SecurityProductInventory inventory, AntiVirusConcern concern) =>
        concern switch
        {
            AntiVirusConcern.Protected =>
                $"protection established by {NamesOf(
                    [.. inventory.ActiveAntiVirusProducts.Where(product =>
                        product.Signatures == SecurityProductSignatures.UpToDate)])} — Windows Security "
                + "Center reports On with signatures current.",
            AntiVirusConcern.SignaturesOutOfDate =>
                $"{NamesOf(inventory.ActiveAntiVirusProducts)} reports On, but every On product reports "
                + "signatures OUT OF DATE. Update it in the product itself.",
            AntiVirusConcern.SignatureStatusUnknown =>
                $"Windows Security Center reports On for {NamesOf(inventory.ActiveAntiVirusProducts)}, but "
                + "at least one On product returned an unrecognized signature status and none reported "
                + "current signatures. Signature currency could not be established; this is not evidence "
                + "that definitions are current or out of date.",
            AntiVirusConcern.ActivityStatusUnknown =>
                $"registered antivirus activity could not be established for "
                + $"{NamesOf(
                    [.. inventory.AntiVirusProducts.Where(product =>
                        product.State == SecurityProductState.Unknown)])}. Windows Security Center returned "
                + "an unrecognized activity state; this is not evidence that the product is On or Off.",
            AntiVirusConcern.NoActiveAntiVirus =>
                $"no registered antivirus reports On ({ExplicitlyInactiveStates(inventory)}). These explicit "
                + "Off, Snoozed or Expired states do not establish active scanning. Open Windows Security "
                + "to review the products.",
            AntiVirusConcern.NoAntiVirusRegistered =>
                "no antivirus is registered with Windows Security Center. On Windows 10 and 11 this is "
                + "unusual — Microsoft Defender registers itself unless it was disabled or removed — and it "
                + "means no product is claiming responsibility for scanning this machine.",
            _ =>
                "unavailable — Windows Security Center could not be read on this machine, so which product "
                + "is protecting it could not be established. This is the normal result on Windows Server "
                + "editions, which do not ship Security Center; it is NOT evidence that no antivirus exists.",
        };

    private static string DescribeShield(
        ControlledFolderAccessPosture shield,
        SecurityProductInventory inventory) => shield.Concern switch
        {
            ControlledFolderAccessConcern.Off =>
                "disabled — Windows' built-in ransomware shield is off, so untrusted programs are not blocked "
                + "from modifying your Documents, Pictures and Desktop; WinSight's decoys detect an attack but "
                + $"cannot stop it. Turn it on in Windows Security ({ControlledFolderAccessReader.SettingsDeepLink}).",
            ControlledFolderAccessConcern.AuditOnly =>
                "audit only — Windows records what it would have blocked but blocks nothing. Switch it on in "
                + $"Windows Security ({ControlledFolderAccessReader.SettingsDeepLink}).",
            ControlledFolderAccessConcern.BlockDiskModificationOnly =>
                "block disk modification only — this mode does not establish protection for folders such as "
                + "Documents, Pictures and Desktop. Review the configured mode in Windows Security "
                + $"({ControlledFolderAccessReader.SettingsDeepLink}).",
            ControlledFolderAccessConcern.AuditDiskModificationOnly =>
                "audit disk modification only — this mode records disk modifications but does not establish folder "
                + "protection. Review the configured mode in Windows Security "
                + $"({ControlledFolderAccessReader.SettingsDeepLink}).",
            ControlledFolderAccessConcern.Protecting =>
                "configured enabled and Defender runtime prerequisites observed — this reports configured and "
                + "operational posture, not a guarantee that every attempted write will be blocked.",
            ControlledFolderAccessConcern.RuntimeRequirementsNotMet =>
                "enabled, but current Defender runtime evidence does not establish Normal mode with antivirus and "
                + "real-time protection enabled. The configured setting alone is not evidence of operational folder protection.",
            ControlledFolderAccessConcern.DefenderNotRunning
                when SecurityProductTriage.Concern(inventory) == AntiVirusConcern.Protected
                     && ProtectedThirdPartyProducts(inventory).Count > 0 =>
                "not active — Microsoft Defender reports that it is not running, while Windows Security Center "
                + $"reports {NamesOf(ProtectedThirdPartyProducts(inventory))} On with current signatures. Controlled "
                + "Folder Access is a Defender feature, so this specific folder shield is not protecting you; the "
                + "third-party antivirus may offer its own ransomware protection, which WinSight cannot read. This "
                + "can be a normal third-party antivirus configuration, but confirm that product's ransomware "
                + "protection in its own console.",
            ControlledFolderAccessConcern.DefenderNotRunning
                when inventory.Reading == SecurityCenterReading.Unavailable =>
                "not active — Microsoft Defender reports that it is not running, while Windows Security Center "
                + "could not be read. WinSight therefore cannot establish whether another antivirus is active. "
                + "Controlled Folder Access is a Defender feature and is not established as protecting these folders.",
            ControlledFolderAccessConcern.DefenderNotRunning
                when SecurityProductTriage.Concern(inventory) == AntiVirusConcern.ActivityStatusUnknown =>
                "not active — Microsoft Defender reports that it is not running, and a registered antivirus returned "
                + "an unrecognized activity state. WinSight cannot establish whether that product is active. Controlled "
                + "Folder Access is a Defender feature and is not established as protecting these folders.",
            ControlledFolderAccessConcern.DefenderNotRunning
                when SecurityProductTriage.Concern(inventory) == AntiVirusConcern.SignatureStatusUnknown =>
                "not active — Microsoft Defender reports that it is not running. Windows Security Center reports "
                + $"{NamesOf(inventory.ActiveAntiVirusProducts)} On, but signature currency is unknown. This does not "
                + "establish current antivirus protection, and Controlled Folder Access is not established as "
                + "protecting these folders.",
            ControlledFolderAccessConcern.DefenderNotRunning
                when SecurityProductTriage.Concern(inventory) == AntiVirusConcern.SignaturesOutOfDate =>
                "not active — Microsoft Defender reports that it is not running. Windows Security Center reports "
                + $"{NamesOf(inventory.ActiveAntiVirusProducts)} On with out-of-date signatures. Update that product; "
                + "Controlled Folder Access is not established as protecting these folders.",
            ControlledFolderAccessConcern.DefenderNotRunning
                when SecurityProductTriage.Concern(inventory) == AntiVirusConcern.Protected =>
                "not active — Microsoft Defender runtime and Windows Security Center returned inconsistent Defender "
                + "evidence. WinSight does not infer a cause. Controlled Folder Access is not established as protecting "
                + "these folders; review Windows Security.",
            ControlledFolderAccessConcern.DefenderNotRunning =>
                "not protecting — Microsoft Defender reports that it is not running, and Windows Security Center "
                + "reports no antivirus On. Controlled Folder Access is a Defender feature and is not established as "
                + "protecting these folders; check "
                + $"which antivirus is active in Windows Security ({ControlledFolderAccessReader.SettingsDeepLink}).",
            ControlledFolderAccessConcern.UnknownMode =>
                $"unsupported mode value {shield.RawStateValue} read; protection not established. Review the configured "
                + $"mode in Windows Security ({ControlledFolderAccessReader.SettingsDeepLink}).",
            _ =>
                "unavailable — the Controlled Folder Access configured or operational posture could not be read on this "
                + "machine, so WinSight cannot establish folder protection.",
        };
}
