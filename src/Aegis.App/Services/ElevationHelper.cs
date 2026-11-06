using System.Diagnostics;
using System.Security.Principal;

namespace Aegis.App.Services;

public static class ElevationHelper
{
    public static bool IsElevated
    {
        get
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }

    public static void RestartElevated()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable) || !File.Exists(executable))
        {
            executable = Path.Combine(AppContext.BaseDirectory, "NDAS.exe");
        }

        if (!File.Exists(executable))
        {
            throw new FileNotFoundException("找不到 NDAS 可执行文件。", executable);
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = AppContext.BaseDirectory
        });

        Aegis.App.App.MainWindow?.Close();
    }
}
