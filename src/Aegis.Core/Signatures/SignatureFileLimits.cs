namespace Aegis.Core.Signatures;

public static class SignatureFileLimits
{
    /// <summary>Upper bound for any downloaded/staged signature data file (2 GiB).</summary>
    public const long MaxBytes = 2L * 1024 * 1024 * 1024;
}
