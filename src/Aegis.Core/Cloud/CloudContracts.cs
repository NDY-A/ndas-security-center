using Aegis.Core.Models;

namespace Aegis.Core.Cloud;

public sealed class CloudOptions
{
    public bool Enabled { get; init; }
    public string Endpoint { get; init; } = string.Empty;
    public string? ApiKey { get; init; }
    public CloudQueryPolicy QueryPolicy { get; init; } = CloudQueryPolicy.SuspiciousOnly;
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);
    public int MinCacheSeconds { get; init; } = 60;
    public int DefaultCacheSeconds { get; init; } = 900;
    public int MaxCacheSeconds { get; init; } = 86_400;
}

public sealed record CloudQueryResult(
    CloudVerdict Verdict,
    int Score,
    string? ThreatName,
    double Confidence,
    int TtlSeconds,
    string? Provider = null)
{
    public bool IsMalicious => Verdict == CloudVerdict.Malicious;
    public bool IsSuspicious => Verdict is CloudVerdict.Suspicious or CloudVerdict.Pua;
}

public sealed record CloudHealthResult(bool Ok, string Message);

public interface ICloudReputationService
{
    bool IsConfigured { get; }
    CloudQueryPolicy QueryPolicy { get; }
    string? LastError { get; }

    Task<CloudQueryResult?> QueryFileAsync(string sha256, long size, CancellationToken cancellationToken = default);

    Task<CloudHealthResult> CheckHealthAsync(CancellationToken cancellationToken = default);
}

public sealed class DisabledCloudReputationService : ICloudReputationService
{
    public static DisabledCloudReputationService Instance { get; } = new();

    public bool IsConfigured => false;
    public CloudQueryPolicy QueryPolicy => CloudQueryPolicy.Never;
    public string? LastError => "云安全查询未配置。";

    public Task<CloudQueryResult?> QueryFileAsync(string sha256, long size, CancellationToken cancellationToken = default) =>
        Task.FromResult<CloudQueryResult?>(null);

    public Task<CloudHealthResult> CheckHealthAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(new CloudHealthResult(false, "云安全查询未配置。"));
}
