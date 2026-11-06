using Microsoft.Win32;

namespace Aegis.App.Services;

public static class AutoStartService
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "NDAS";
    private const string LegacyValueName = "Aegis";

    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath);
            return key?.GetValue(ValueName) is string value &&
                   value.Contains("NDAS", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static void SetEnabled(bool enabled)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
            if (key is null)
            {
                return;
            }

            if (enabled)
            {
                var executable = Environment.ProcessPath;
                if (string.IsNullOrWhiteSpace(executable))
                {
                    return;
                }

                key.SetValue(ValueName, $"\"{executable}\" --background");
                DeleteLegacyIfOurs(key);
            }
            else
            {
                if (key.GetValue(ValueName) is string existing &&
                    existing.Contains("NDAS", StringComparison.OrdinalIgnoreCase))
                {
                    key.DeleteValue(ValueName, throwOnMissingValue: false);
                }

                DeleteLegacyIfOurs(key);
            }
        }
        catch
        {
            // The setting UI reports failures; the registry entry is best-effort.
        }
    }

    private static void DeleteLegacyIfOurs(RegistryKey key)
    {
        if (key.GetValue(LegacyValueName) is string legacy &&
            legacy.Contains(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase))
        {
            key.DeleteValue(LegacyValueName, throwOnMissingValue: false);
        }
    }
}
