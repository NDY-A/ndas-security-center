namespace Aegis.Core.Infrastructure;

public static class AppPaths
{
    public const string AppFolderName = "NDAS";
    public const string LegacyAppFolderName = "Aegis";

    private static string LocalDataRoot =>
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    public static string DataRoot => Path.Combine(LocalDataRoot, AppFolderName);

    public static string LegacyDataRoot => Path.Combine(LocalDataRoot, LegacyAppFolderName);

    public static string SignatureRoot => Path.Combine(DataRoot, "signatures");

    public static string SecretsRoot => Path.Combine(DataRoot, "secrets");

    public static string SettingsFile => Path.Combine(DataRoot, "settings.json");

    public static string LogsRoot => Path.Combine(DataRoot, "logs");

    public static string QuarantineRoot => Path.Combine(DataRoot, "quarantine");

    public static void EnsureDirectory(string path)
    {
        Directory.CreateDirectory(path);
        return;
    }

    public static void MigrateLegacyData()
    {
        try
        {
            if (!Directory.Exists(LegacyDataRoot) || Directory.Exists(DataRoot))
            {
                return;
            }

            try
            {
                Directory.Move(LegacyDataRoot, DataRoot);
            }
            catch
            {
                CopyDirectory(LegacyDataRoot, DataRoot);
            }
        }
        catch
        {
            // Migration is best-effort; a fresh data directory still works.
        }
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(source, directory)));
        }

        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var target = Path.Combine(destination, Path.GetRelativePath(source, file));
            var parent = Path.GetDirectoryName(target);
            if (!string.IsNullOrWhiteSpace(parent))
            {
                Directory.CreateDirectory(parent);
            }

            File.Copy(file, target, overwrite: false);
        }
    }
}
