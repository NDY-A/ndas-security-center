using System.Threading.Channels;

namespace Aegis.Sandbox;

public sealed class SandboxQueue
{
    private readonly Channel<SandboxJob> _channel;

    public SandboxQueue(int capacity)
    {
        _channel = Channel.CreateBounded<SandboxJob>(new BoundedChannelOptions(Math.Max(1, capacity))
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
    }

    public int Depth => _channel.Reader.Count;

    public IAsyncEnumerable<SandboxJob> ReadAllAsync(CancellationToken cancellationToken) =>
        _channel.Reader.ReadAllAsync(cancellationToken);

    public bool TryEnqueue(SandboxJob job) => _channel.Writer.TryWrite(job);

    public void Complete() => _channel.Writer.TryComplete();
}
