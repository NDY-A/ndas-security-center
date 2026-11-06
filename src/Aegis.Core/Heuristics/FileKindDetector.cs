using Aegis.Core.Models;

namespace Aegis.Core.Heuristics;

public static class FileKindDetector
{
    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".hta", ".bat", ".cmd", ".py", ".pyw", ".sh"
    };

    private static readonly HashSet<string> MacroExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm", ".xlam"
    };

    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".rtf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".one"
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab",
        ".iso", ".img", ".vhd", ".vhdx", ".msi", ".msp", ".appx", ".msix"
    };

    private static readonly HashSet<string> ShortcutExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".lnk", ".url", ".website"
    };

    public static FileKind Detect(string fileName, ReadOnlySpan<byte> header)
    {
        if (header.Length >= 2 && header[0] == (byte)'M' && header[1] == (byte)'Z')
        {
            return FileKind.PortableExecutable;
        }

        var extension = Path.GetExtension(fileName);
        if (ScriptExtensions.Contains(extension))
        {
            return FileKind.Script;
        }

        if (MacroExtensions.Contains(extension))
        {
            return FileKind.MacroDocument;
        }

        if (ShortcutExtensions.Contains(extension))
        {
            return FileKind.Shortcut;
        }

        if (ArchiveExtensions.Contains(extension))
        {
            return FileKind.Archive;
        }

        if (DocumentExtensions.Contains(extension))
        {
            return FileKind.Document;
        }

        return FileKind.Unknown;
    }

    public static bool SupportsContentHeuristics(FileKind kind) => kind is
        FileKind.PortableExecutable or
        FileKind.Script or
        FileKind.MacroDocument or
        FileKind.Shortcut or
        FileKind.Document;

    public static bool SupportsCloudLookup(FileKind kind, CloudQueryPolicy policy) => policy switch
    {
        CloudQueryPolicy.Never => false,
        CloudQueryPolicy.All => true,
        CloudQueryPolicy.ExecutablesAndScripts => kind is FileKind.PortableExecutable or FileKind.Script or FileKind.Archive or FileKind.MacroDocument or FileKind.Shortcut,
        _ => false
    };
}
