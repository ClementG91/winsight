namespace WinSight.Certificates;

/// <summary>What a certificate store makes Windows do with the certificates it holds.</summary>
public enum CertificateTrustRole
{
    /// <summary><c>Root</c>: anything chaining to it is trusted, for TLS and code signing alike.</summary>
    Root,

    /// <summary>
    /// <c>TrustedPublisher</c>: code signed by it runs without the prompts other signed code gets
    /// (Office macros, the <c>AllSigned</c> PowerShell policy, driver and ClickOnce installs).
    /// </summary>
    TrustedPublisher,

    /// <summary><c>Disallowed</c>: explicitly distrusted, whatever it chains to. Protective.</summary>
    Disallowed,
}
