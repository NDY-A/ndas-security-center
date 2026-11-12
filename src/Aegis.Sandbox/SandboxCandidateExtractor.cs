using System.IO.Compression;
using System.Security.Cryptography;
using Aegis.Core.Heuristics;
using Aegis.Core.Models;

namespace Aegis.Sandbox;

public static class SandboxCandidateExtractor
{
    public const int MaxEntries = 64;
    public const long MaxEntryBytes = 32L * 1024 * 1024;
    public const long MaxTotalBytes = 256L * 1024 * 1024;
    private const double ExecutableSectionEntropyThreshold = 7.2;
    private const double FileEntropyThreshold = 7.5;

    public static bool IsZipCandidate(FileScanResult result)
    {
        if (result.Kind != FileKind.Archive && !result.FileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            using var stream = File.OpenRead(result.FilePath);
            Span<byte> header = stackalloc byte[4];
            return stream.Read(header) == 4 &&
                   header[0] == 0x50 && header[1] == 0x4B &&
                   ((header[2] == 0x03 && header[3] == 0x04) || (header[2] == 0x05 && header[3] == 0x06));
        }
        catch
        {
            return false;
        }
    }

    public static IReadOnlyList<SandboxCandidate> Extract(
        FileScanResult archive,
        string stagingRoot,
        SandboxOptions options,
        out string error)
    {
        error = string.Empty;
        var candidates = new List<SandboxCandidate>();
        var directory = Path.Combine(stagingRoot, Guid.NewGuid().ToString("N"));
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long totalBytes = 0;

        try
        {
            using var stream = File.OpenRead(archive.FilePath);
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
            var entryCount = 0;
            foreach (var entry in zip.Entries)
            {
                if (entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\'))
                {
                    continue;
                }

                if (++entryCount > MaxEntries || totalBytes >= MaxTotalBytes)
                {
                    break;
                }

                if (entry.Length <= 0 || entry.Length > MaxEntryBytes ||
                    entry.Length < options.MinFileSizeBytes)
                {
                    continue;
                }

                byte[] data;
                try
                {
                    using var entryStream = entry.Open();
                    using var memory = new MemoryStream((int)Math.Min(entry.Length, MaxEntryBytes));
                    var buffer = new byte[128 * 1024];
                    long readTotal = 0;
                    int read;
                    while ((read = entryStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        readTotal += read;
                        if (readTotal > MaxEntryBytes || totalBytes + readTotal > MaxTotalBytes)
                        {
                            break;
                        }

                        memory.Write(buffer, 0, read);
                    }

                    totalBytes += readTotal;
                    data = memory.ToArray();
                }
                catch
                {
                    continue;
                }

                if (!IsHighEntropyPe(data, out _))
                {
                    continue;
                }

                var sha256 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
                if (!seen.Add(sha256))
                {
                    continue;
                }

                Directory.CreateDirectory(directory);
                var staged = Path.Combine(directory, sha256 + ".bin");
                File.WriteAllBytes(staged, data);
                candidates.Add(new SandboxCandidate(
                    archive.FilePath,
                    sha256,
                    data.Length,
                    null,
                    "HIPS.SANDBOX.ARCHIVE",
                    ParentArchivePath: archive.FilePath,
                    ArchiveEntryName: entry.FullName,
                    AnalysisPath: staged,
                    CleanupDirectory: directory));
            }
        }
        catch (Exception exception)
        {
            error = "压缩包候选提取失败：" + exception.Message;
        }

        if (candidates.Count == 0 && Directory.Exists(directory))
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch
            {
                // Best effort.
            }
        }

        return candidates;
    }

    public static bool IsHighEntropyPe(ReadOnlySpan<byte> data, out string? reason)
    {
        reason = null;
        if (data.Length < 0x100 || data[0] != (byte)'M' || data[1] != (byte)'Z')
        {
            reason = "不是 PE 文件";
            return false;
        }

        var lfanew = BitConverter.ToInt32(data[0x3C..0x40]);
        if (lfanew <= 0 || lfanew + 24 > data.Length ||
            data[lfanew] != (byte)'P' || data[lfanew + 1] != (byte)'E' ||
            data[lfanew + 2] != 0 || data[lfanew + 3] != 0)
        {
            reason = "PE 头无效";
            return false;
        }

        var machine = BitConverter.ToUInt16(data[(lfanew + 4)..(lfanew + 6)]);
        if (machine is not (0x014C or 0x8664 or 0xAA64))
        {
            reason = "不是 Windows PE";
            return false;
        }

        var sectionCount = BitConverter.ToUInt16(data[(lfanew + 6)..(lfanew + 8)]);
        var optionalHeaderSize = BitConverter.ToUInt16(data[(lfanew + 20)..(lfanew + 22)]);
        var optionalOffset = lfanew + 24;
        if (optionalOffset + 2 > data.Length || sectionCount > 96)
        {
            reason = "PE 可选头无效";
            return false;
        }

        var magic = BitConverter.ToUInt16(data[optionalOffset..(optionalOffset + 2)]);
        int dataDirectoryOffset;
        int dataDirectoryCountOffset;
        if (magic == 0x10B)
        {
            dataDirectoryCountOffset = optionalOffset + 92;
            dataDirectoryOffset = optionalOffset + 96;
        }
        else if (magic == 0x20B)
        {
            dataDirectoryCountOffset = optionalOffset + 108;
            dataDirectoryOffset = optionalOffset + 112;
        }
        else
        {
            reason = "未知 PE 格式";
            return false;
        }

        if (dataDirectoryCountOffset + 4 <= data.Length)
        {
            var directoryCount = BitConverter.ToInt32(data[dataDirectoryCountOffset..(dataDirectoryCountOffset + 4)]);
            if (directoryCount > 14)
            {
                var comOffset = dataDirectoryOffset + 14 * 8;
                if (comOffset + 8 <= data.Length && BitConverter.ToInt32(data[comOffset..(comOffset + 4)]) != 0)
                {
                    reason = ".NET 程序集";
                    return false;
                }
            }
        }

        var fileEntropy = EntropyCalculator.Calculate(data);
        if (fileEntropy >= FileEntropyThreshold)
        {
            return true;
        }

        var sectionTable = optionalOffset + optionalHeaderSize;
        for (var index = 0; index < sectionCount; index++)
        {
            var offset = sectionTable + index * 40;
            if (offset + 40 > data.Length)
            {
                break;
            }

            var characteristics = BitConverter.ToUInt32(data[(offset + 36)..(offset + 40)]);
            if ((characteristics & 0x20000000) == 0)
            {
                continue;
            }

            var rawSize = (int)BitConverter.ToUInt32(data[(offset + 16)..(offset + 20)]);
            var rawPointer = BitConverter.ToInt32(data[(offset + 20)..(offset + 24)]);
            if (rawSize <= 0 || rawPointer < 0 || rawPointer + (long)rawSize > data.Length)
            {
                continue;
            }

            if (EntropyCalculator.Calculate(data.Slice(rawPointer, rawSize)) > ExecutableSectionEntropyThreshold)
            {
                return true;
            }
        }

        reason = "未达到高熵阈值";
        return false;
    }
}
