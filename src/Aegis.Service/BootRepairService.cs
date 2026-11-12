using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Aegis.Service;

public sealed record BootRepairOutcome(bool Success, string Detail, string? BackupPath, bool IsUefi);

/// <summary>
/// Conservative one-shot boot repair: export the BCD store, refresh Windows boot
/// files with bcdboot, then verify. The MBR and other operating systems' boot
/// entries are deliberately left untouched (this machine multiboots).
/// </summary>
public static class BootRepairService
{
    public static async Task<BootRepairOutcome> RepairOnceAsync(CancellationToken cancellationToken)
    {
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var bcdedit = Path.Combine(systemRoot, "System32", "bcdedit.exe");
        var bcdboot = Path.Combine(systemRoot, "System32", "bcdboot.exe");
        if (!File.Exists(bcdedit) || !File.Exists(bcdboot))
        {
            return new BootRepairOutcome(false, "找不到 bcdedit.exe / bcdboot.exe，已跳过引导修复。", null, IsUefi());
        }

        var uefi = IsUefi();
        var backupDirectory = Path.Combine(ServicePaths.DataRoot, "backup", "boot");
        Directory.CreateDirectory(backupDirectory);
        var backupPath = Path.Combine(backupDirectory, $"BCD-{DateTime.Now:yyyyMMdd-HHmmss}.bcd");

        var export = await RunAsync(bcdedit, $"/export \"{backupPath}\"", TimeSpan.FromSeconds(60), cancellationToken)
            .ConfigureAwait(false);
        if (!export.Success || !File.Exists(backupPath))
        {
            return new BootRepairOutcome(false,
                "BCD 备份失败，已中止引导修复：" + Describe(export), null, uefi);
        }

        TryCopyStoreFile(systemRoot, backupDirectory);

        var bcdbootArguments = uefi ? $"\"{systemRoot}\" /f UEFI" : $"\"{systemRoot}\"";
        var repair = await RunAsync(bcdboot, bcdbootArguments, TimeSpan.FromSeconds(120), cancellationToken)
            .ConfigureAwait(false);
        var verify = await RunAsync(bcdedit, "/enum {default}", TimeSpan.FromSeconds(30), cancellationToken)
            .ConfigureAwait(false);

        if (!repair.Success || !verify.Success)
        {
            var restore = await RunAsync(bcdedit, $"/import \"{backupPath}\"", TimeSpan.FromSeconds(60), cancellationToken)
                .ConfigureAwait(false);
            var restoreText = restore.Success ? "已用备份回滚 BCD 配置。" : "BCD 回滚失败，请用备份文件手工恢复。";
            return new BootRepairOutcome(false,
                $"引导修复失败（{Describe(repair)}；校验：{Describe(verify)}）。{restoreText}", backupPath, uefi);
        }

        return new BootRepairOutcome(true,
            uefi
                ? "已用 bcdboot 刷新 UEFI 引导文件；未改动 MBR 与其他系统的引导项。"
                : "已刷新 Windows 引导文件；为保护多系统，未改写 MBR。",
            backupPath, uefi);
    }

    private static void TryCopyStoreFile(string systemRoot, string backupDirectory)
    {
        try
        {
            var store = Path.Combine(systemRoot, "Boot", "BCD");
            if (File.Exists(store))
            {
                File.Copy(store, Path.Combine(backupDirectory, $"BCD-store-{DateTime.Now:yyyyMMdd-HHmmss}.bak"),
                    overwrite: false);
            }
        }
        catch
        {
            // Export above is the authoritative backup; this copy is best-effort.
        }
    }

    private static string Describe(CommandResult result)
    {
        if (result.TimedOut)
        {
            return "命令超时";
        }

        if (!string.IsNullOrWhiteSpace(result.Error))
        {
            return $"退出码 {result.ExitCode}：{Trim(result.Error)}";
        }

        return $"退出码 {result.ExitCode}：{Trim(result.Output)}";
    }

    private static string Trim(string value)
    {
        var line = value.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(segment => !string.IsNullOrWhiteSpace(segment))?.Trim() ?? string.Empty;
        return line.Length <= 240 ? line : line[..240] + "…";
    }

    private static async Task<CommandResult> RunAsync(string fileName, string arguments, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
                }
            };

            process.Start();
            var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
            using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCancellation.CancelAfter(timeout);

            try
            {
                await process.WaitForExitAsync(timeoutCancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // The process may have already exited.
                }

                return new CommandResult(false, -1, string.Empty, "命令执行超时", true);
            }

            var output = await outputTask.ConfigureAwait(false);
            var error = await errorTask.ConfigureAwait(false);
            return new CommandResult(process.ExitCode == 0, process.ExitCode, output, error, false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new CommandResult(false, -1, string.Empty, exception.Message, false);
        }
    }

    private static bool IsUefi()
    {
        try
        {
            if (GetFirmwareType(out var firmwareType))
            {
                return firmwareType == FirmwareTypeUefi;
            }
        }
        catch
        {
            // Fall through to the conservative default.
        }

        return false;
    }

    private const int FirmwareTypeUefi = 2;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFirmwareType(out int firmwareType);

    private readonly record struct CommandResult(bool Success, int ExitCode, string Output, string Error, bool TimedOut);
}
