namespace Aegis.Agent;

public sealed class AgentApiOptions
{
    public int Port { get; init; } = 17_483;
    public int MaxConcurrentRequests { get; init; } = 8;
    public int MaxHeaderBytes { get; init; } = 32 * 1024;
    public int MaxBodyBytes { get; init; } = 64 * 1024;
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(20);
    public string ApiVersion { get; init; } = "1.0";
}
