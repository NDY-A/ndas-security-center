using System.Diagnostics;
using System.IO.Pipes;
using System.Text;

namespace Aegis.App.Services;

/// <summary>
/// One NDAS UI instance per interactive session. Secondary launches forward a
/// short command to the primary instance and exit, so the RunOnce post-remediation
/// launch cannot collide with the normal --background autostart.
/// </summary>
public sealed class SingleInstanceService : IDisposable
{
    private static readonly string SessionTag = Process.GetCurrentProcess().SessionId.ToString();
    private static readonly string MutexName = $@"Local\NDAS.SingleInstance.{SessionTag}";
    private static readonly string PipeName = $"NDAS.App.Instance.{SessionTag}";

    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);
    private Mutex? _mutex;
    private CancellationTokenSource? _cancellation;
    private Task? _server;

    public event EventHandler<string>? CommandReceived;

    public bool TryAcquire()
    {
        var mutex = new Mutex(initiallyOwned: true, MutexName, out var createdNew);
        if (!createdNew)
        {
            mutex.Dispose();
            return false;
        }

        _mutex = mutex;
        _cancellation = new CancellationTokenSource();
        var token = _cancellation.Token;
        _server = Task.Run(() => ServerLoopAsync(token), CancellationToken.None);
        return true;
    }

    public static bool TrySend(string command, int timeoutMs = 3000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.Out, PipeOptions.Asynchronous);
                using var attempt = new CancellationTokenSource(500);
                pipe.ConnectAsync(attempt.Token).GetAwaiter().GetResult();
                using var writer = new StreamWriter(pipe, Utf8, bufferSize: 256, leaveOpen: true) { AutoFlush = true };
                writer.WriteLine(command);
                return true;
            }
            catch
            {
                Thread.Sleep(200);
            }
        }

        return false;
    }

    private async Task ServerLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = new NamedPipeServerStream(PipeName, PipeDirection.In, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                using var reader = new StreamReader(pipe, Utf8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
                var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(line))
                {
                    try
                    {
                        CommandReceived?.Invoke(this, line.Trim());
                    }
                    catch
                    {
                        // Command handlers must not kill the listener.
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                try
                {
                    await Task.Delay(200, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    public void Dispose()
    {
        try
        {
            _cancellation?.Cancel();
            _server?.Wait(TimeSpan.FromMilliseconds(500));
        }
        catch
        {
            // Best-effort teardown.
        }

        _cancellation?.Dispose();
        _cancellation = null;
        if (_mutex is not null)
        {
            try
            {
                _mutex.ReleaseMutex();
            }
            catch
            {
                // The mutex may not be owned anymore.
            }

            _mutex.Dispose();
            _mutex = null;
        }
    }
}
