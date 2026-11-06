namespace Aegis.Agent;

internal sealed class AgentScanStartRequest
{
    public string? Path { get; set; }
    public string? Profile { get; set; }
    public long? MaxFileSizeBytes { get; set; }
    public bool? QueryCloud { get; set; }
    public string? CloudPolicy { get; set; }
}
