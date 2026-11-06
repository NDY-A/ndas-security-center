namespace Aegis.Service;

public static class ServicePaths
{
    public static string DataRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NDAS");

    public static string SettingsFile => Path.Combine(DataRoot, "service-settings.json");

    public static string LogsRoot => Path.Combine(DataRoot, "logs");

    public static string SharedSignatureRoot => Path.Combine(DataRoot, "signatures");

    public static string? ResolveSeedDirectory(string? explicitSeed = null)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(explicitSeed))
        {
            candidates.Add(explicitSeed);
        }

        var baseDirectory = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        candidates.Add(Path.GetFullPath(Path.Combine(baseDirectory, "..", "Seed")));
        candidates.Add(Path.Combine(baseDirectory, "Seed"));

        var directory = new DirectoryInfo(baseDirectory);
        for (var depth = 0; depth < 8 && directory is not null; depth++, directory = directory.Parent)
        {
            candidates.Add(Path.Combine(directory.FullName, "Seed"));
            candidates.Add(Path.Combine(directory.FullName, "data", "seed"));
        }

        foreach (var candidate in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (Directory.Exists(candidate) && File.Exists(Path.Combine(candidate, "manifest.json")))
            {
                return candidate;
            }
        }

        return null;
    }
}
