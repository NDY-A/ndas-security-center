using System.Diagnostics;

namespace Aegis.Core.Remediation;

public static class ProcessRemediator
{
    private static readonly HashSet<string> ProtectedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "registry", "memory compression", "smss", "csrss", "wininit", "winlogon",
        "services", "lsass", "lsaiso", "svchost", "dwm", "fontdrvhost", "sihost", "taskhostw",
        "runtimebroker", "explorer", "spoolsv", "audiodg", "wudfhost", "searchindexer",
        "securityhealthservice", "windefend", "msmpeng", "nissrv", "smartscreen", "sgrmbroker",
        "ndasservice", "ndas", "aegis"
    };

    public static bool TryTerminate(int pid, string? expectedPath, IReadOnlyList<string> exclusions,
        out string detail)
        => TryTerminate(pid, expectedPath, null, exclusions, out detail);

    public static bool TryTerminate(int pid, string? expectedPath, DateTime? expectedStartTime,
        IReadOnlyList<string> exclusions, out string detail)
    {
        detail = string.Empty;
        if (pid <= 4 || pid == Environment.ProcessId)
        {
            detail = "PID 无效或为防护进程自身";
            return false;
        }

        Process process;
        try
        {
            process = Process.GetProcessById(pid);
        }
        catch
        {
            detail = "进程已退出";
            return false;
        }

        using (process)
        {
            if (ProtectedNames.Contains(process.ProcessName))
            {
                detail = "受保护的系统进程，跳过终止";
                return false;
            }

            string? imagePath = null;
            try
            {
                imagePath = process.MainModule?.FileName;
            }
            catch
            {
                // Protected processes deny module access.
            }

            if (string.IsNullOrWhiteSpace(imagePath))
            {
                detail = "无法读取进程映像路径，跳过终止";
                return false;
            }

            if (!string.IsNullOrWhiteSpace(expectedPath) &&
                !string.Equals(Path.GetFullPath(imagePath), Path.GetFullPath(expectedPath),
                    StringComparison.OrdinalIgnoreCase))
            {
                detail = "进程映像已变化（疑似 PID 复用），跳过终止";
                return false;
            }

            if (expectedStartTime is DateTime expected)
            {
                try
                {
                    if ((process.StartTime - expected).Duration() > TimeSpan.FromSeconds(2))
                    {
                        detail = "进程启动时间不匹配（疑似 PID 复用），跳过终止";
                        return false;
                    }
                }
                catch
                {
                    detail = "无法读取进程启动时间，跳过终止";
                    return false;
                }
            }

            var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (windowsDirectory.Length > 0 && IsUnder(imagePath, windowsDirectory))
            {
                detail = "进程映像位于系统目录，跳过终止";
                return false;
            }

            foreach (var exclusion in exclusions)
            {
                if (IsUnder(imagePath, exclusion))
                {
                    detail = "进程映像位于排除项，跳过终止";
                    return false;
                }
            }

            try
            {
                process.Kill(entireProcessTree: false);
                if (!process.WaitForExit(3000))
                {
                    detail = "已请求终止进程，但进程未在 3 秒内退出";
                    return false;
                }

                return true;
            }
            catch (Exception exception)
            {
                detail = "终止进程失败：" + exception.Message;
                return false;
            }
        }
    }

    private static bool IsUnder(string path, string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }

        var root = directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        return path.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
               path.Equals(directory, StringComparison.OrdinalIgnoreCase);
    }
}
