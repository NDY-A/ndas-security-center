using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Aegis.Core.Models;

namespace Aegis.Core.Heuristics;

public sealed record PeAnalysis(
    PeFileInfo? Info,
    IReadOnlyList<Detection> Findings,
    IReadOnlyList<string> Notes);

public static class PortableExecutableAnalyzer
{
    private const int MaxSectionSampleBytes = 4 * 1024 * 1024;
    private const int MaxImportsPerDll = 2048;
    private const int MaxDlls = 128;

    private static readonly string[] PackerSectionMarkers =
    {
        "upx", "aspack", ".adata", ".packed", "themida", ".vmp", ".enigma",
        "mpress", ".petite", ".nsp", ".boom", ".pklst", "pec2", "pec1", ".perplex"
    };

    private static readonly HashSet<string> InjectionApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
        "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext", "NtCreateThreadEx",
        "RtlCreateUserThread", "NtMapViewOfSection", "ZwWriteVirtualMemory"
    };

    private static readonly HashSet<string> CredentialApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "MiniDumpWriteDump", "CredEnumerateW", "CredReadW", "LsaEnumerateLogonSessions",
        "CryptUnprotectData", "SamQueryInformationUser", "NtOpenProcess"
    };

    private static readonly HashSet<string> PersistenceApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "CreateServiceW", "StartServiceW", "RegSetValueExW", "RegCreateKeyExW", "SchTasks"
    };

    private static readonly HashSet<string> AntiAnalysisApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "NtSetInformationThread", "BlockInput", "OutputDebugStringW"
    };

    private static readonly HashSet<string> NetworkApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "InternetOpenUrlW", "InternetOpenW", "URLDownloadToFileW", "WinHttpOpen",
        "WinHttpSendRequest", "WSAStartup", "connect", "send", "recv", "HttpSendRequestW"
    };

    public static PeAnalysis Analyze(string path)
    {
        var findings = new List<Detection>();
        var notes = new List<string>();

        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                64 * 1024,
                FileOptions.RandomAccess);
            using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
            var headers = peReader.PEHeaders;
            var peHeader = headers.PEHeader;
            if (peHeader is null)
            {
                return CorruptHeaders("PE 头缺失。");
            }

            var coff = headers.CoffHeader;
            var isDotNet = headers.CorHeader is not null;
            var isDll = (coff.Characteristics & Characteristics.Dll) != 0;
            var sections = new List<PeSectionInfo>();
            var hasWritableExecutable = false;
            var hasPackerName = false;
            var maxExecutableEntropy = 0.0;
            var hasHighEntropyExecutable = false;
            var entryPoint = peHeader.AddressOfEntryPoint;
            var entryPointInsideSection = entryPoint == 0;

            foreach (var section in headers.SectionHeaders)
            {
                var name = string.IsNullOrWhiteSpace(section.Name) ? "(unnamed)" : section.Name.TrimEnd('\0');
                var isExecutable = (section.SectionCharacteristics & SectionCharacteristics.MemExecute) != 0;
                var isWritable = (section.SectionCharacteristics & SectionCharacteristics.MemWrite) != 0;
                if (isExecutable && isWritable)
                {
                    hasWritableExecutable = true;
                }

                if (PackerSectionMarkers.Any(marker => name.Contains(marker, StringComparison.OrdinalIgnoreCase)))
                {
                    hasPackerName = true;
                }

                var sizeWithinSection = entryPoint > 0 &&
                                        entryPoint >= section.VirtualAddress &&
                                        entryPoint < section.VirtualAddress + Math.Max(section.VirtualSize, section.SizeOfRawData);
                entryPointInsideSection |= sizeWithinSection;

                var entropy = 0.0;
                var rawSize = 0L;
                if (section.SizeOfRawData > 0)
                {
                    var block = peReader.GetSectionData(section.VirtualAddress);
                    var length = Math.Min(block.Length, Math.Min(section.SizeOfRawData, MaxSectionSampleBytes));
                    if (length > 0)
                    {
                        var bytes = block.GetContent(0, length).ToArray();
                        entropy = EntropyCalculator.Calculate(bytes);
                        rawSize = section.SizeOfRawData;
                    }
                }

                if (isExecutable && entropy > 7.2)
                {
                    hasHighEntropyExecutable = true;
                    maxExecutableEntropy = Math.Max(maxExecutableEntropy, entropy);
                }

                sections.Add(new PeSectionInfo
                {
                    Name = name,
                    VirtualSize = section.VirtualSize,
                    RawSize = rawSize,
                    Entropy = Math.Round(entropy, 3),
                    IsExecutable = isExecutable,
                    IsWritable = isWritable
                });
            }

            var imports = ReadImports(peReader, peHeader, isDotNet, out var importedDlls, out var importParseNote);
            if (importParseNote is not null)
            {
                notes.Add(importParseNote);
            }

            if (hasWritableExecutable)
            {
                findings.Add(new Detection
                {
                    RuleId = "Heur.PE.WXSection",
                    Name = "Heur:PE/WritableExecutableSection",
                    Description = "PE 包含同时可写且可执行的节区，常见于壳、注入器和自修改代码。",
                    Score = 25,
                    Severity = ThreatSeverity.High,
                    Source = DetectionSource.Heuristic,
                    Evidence = string.Join(", ", sections.Where(x => x.IsExecutable && x.IsWritable).Select(x => x.Name))
                });
            }

            if (hasPackerName)
            {
                findings.Add(new Detection
                {
                    RuleId = "Heur.PE.PackerSection",
                    Name = "Heur:PE/PackerSection",
                    Description = "发现 UPX/Themida/VMProtect 等打包器特征节区。打包本身不必然是恶意，但会降低静态可读性。",
                    Score = 28,
                    Severity = ThreatSeverity.High,
                    Source = DetectionSource.Heuristic,
                    Evidence = string.Join(", ", sections.Where(x => PackerSectionMarkers.Any(marker => x.Name.Contains(marker, StringComparison.OrdinalIgnoreCase))).Select(x => x.Name))
                });
            }

            if (hasHighEntropyExecutable)
            {
                findings.Add(new Detection
                {
                    RuleId = "Heur.PE.HighEntropy",
                    Name = "Heur:PE/HighEntropyCode",
                    Description = "可执行节区的熵值异常高，提示代码被压缩、加密或混淆。",
                    Score = maxExecutableEntropy >= 7.5 ? 24 : 18,
                    Severity = ThreatSeverity.Medium,
                    Source = DetectionSource.Heuristic,
                    Evidence = $"最高熵 {maxExecutableEntropy:F2}/8.00"
                });
            }

            if (entryPoint != 0 && !entryPointInsideSection)
            {
                findings.Add(new Detection
                {
                    RuleId = "Heur.PE.EntryPointOutsideSections",
                    Name = "Heur:PE/EntryPointOutsideSections",
                    Description = "入口点位于任何节区之外，是畸形或加壳 PE 的常见特征。",
                    Score = 25,
                    Severity = ThreatSeverity.High,
                    Source = DetectionSource.Heuristic,
                    Evidence = $"EntryPoint RVA 0x{entryPoint:X}"
                });
            }

            if (!isDotNet && imports.Count == 0)
            {
                findings.Add(new Detection
                {
                    RuleId = "Heur.PE.NoImports",
                    Name = "Heur:PE/NoVisibleImports",
                    Description = "PE 没有可解析的导入表；部分加壳程序会动态解析 API。",
                    Score = 8,
                    Severity = ThreatSeverity.Low,
                    Source = DetectionSource.Heuristic
                });
            }

            AddImportFindings(findings, imports, hasHighEntropyExecutable, hasWritableExecutable, hasPackerName);

            var authenticode = ReadAuthenticodeInfo(path, notes);
            if (authenticode.State == AuthenticodeState.Invalid)
            {
                findings.Add(new Detection
                {
                    RuleId = "Heur.PE.SignatureMismatch",
                    Name = "Heur:PE/SignatureMismatch",
                    Description = "文件带有数字签名但签名校验失败（内容被修改、签名被截取或盗用），常见于白加黑宿主劫持/补丁加载器。",
                    Score = 45,
                    Severity = ThreatSeverity.Medium,
                    Source = DetectionSource.Heuristic,
                    Evidence = authenticode.Subject
                });
            }

            var timestamp = ParseLinkerTimestamp(coff.TimeDateStamp, notes);
            var info = new PeFileInfo
            {
                Machine = coff.Machine.ToString(),
                Subsystem = peHeader.Subsystem.ToString(),
                IsDotNet = isDotNet,
                IsDll = isDll,
                LinkerTimestamp = timestamp,
                SectionCount = sections.Count,
                Sections = sections,
                ImportedDlls = importedDlls.Take(64).ToArray(),
                ImportedFunctions = imports.Take(200).ToArray(),
                HasAuthenticodeCertificate = authenticode.HasCertificate,
                SignerSubject = authenticode.Subject,
                AuthenticodeNote = authenticode.Note
            };

            return new PeAnalysis(info, findings, notes);
        }
        catch (BadImageFormatException)
        {
            return CorruptHeaders("PE 结构损坏或不是有效的可执行文件。");
        }
        catch (IOException)
        {
            return new PeAnalysis(null, Array.Empty<Detection>(), new[] { "PE 分析时读取文件失败，仅完成哈希匹配。" });
        }
        catch (UnauthorizedAccessException)
        {
            return new PeAnalysis(null, Array.Empty<Detection>(), new[] { "没有读取该 PE 的权限，仅完成哈希匹配。" });
        }
    }

    private static void AddImportFindings(
        List<Detection> findings,
        IReadOnlySet<string> imports,
        bool highEntropy,
        bool writableExecutable,
        bool packer)
    {
        var injection = imports.Where(InjectionApis.Contains).ToArray();
        if (injection.Length > 0)
        {
            findings.Add(new Detection
            {
                RuleId = "Heur.PE.InjectionImports",
                Name = "Heur:PE/ProcessInjectionImports",
                Description = "导入表包含跨进程内存写入或远程线程 API，属于高风险组合。",
                Score = Math.Min(30, 12 + (injection.Length - 1) * 8),
                Severity = injection.Length >= 2 ? ThreatSeverity.Critical : ThreatSeverity.High,
                Source = DetectionSource.Heuristic,
                Evidence = string.Join(", ", injection.Take(8))
            });
        }

        var credentials = imports.Where(CredentialApis.Contains).ToArray();
        if (credentials.Length > 0)
        {
            findings.Add(new Detection
            {
                RuleId = "Heur.PE.CredentialImports",
                Name = "Heur:PE/CredentialAccessImports",
                Description = "导入表包含凭据读取、LSASS 转储或浏览器密码解密相关 API。",
                Score = Math.Min(35, 24 + credentials.Length * 4),
                Severity = ThreatSeverity.Critical,
                Source = DetectionSource.Heuristic,
                Evidence = string.Join(", ", credentials.Take(8))
            });
        }

        var antiAnalysis = imports.Where(AntiAnalysisApis.Contains).ToArray();
        if (injection.Length > 0 && antiAnalysis.Length > 0)
        {
            findings.Add(new Detection
            {
                RuleId = "Heur.PE.InjectionAntiAnalysis",
                Name = "Heur:PE/InjectionWithAntiAnalysis",
                Description = "同时出现进程注入与反调试/反分析 API，行为链高度可疑。",
                Score = 15,
                Severity = ThreatSeverity.High,
                Source = DetectionSource.Heuristic,
                Evidence = string.Join(", ", antiAnalysis.Take(6))
            });
        }

        var persistence = imports.Where(PersistenceApis.Contains).ToArray();
        var network = imports.Where(NetworkApis.Contains).ToArray();
        if (injection.Length > 0 && (persistence.Length > 0 || network.Length > 0))
        {
            findings.Add(new Detection
            {
                RuleId = "Heur.PE.InjectionChain",
                Name = "Heur:PE/InjectionAndDeliveryChain",
                Description = "进程注入与持久化/网络下载能力同时存在，符合加载器或 RAT 的行为组合。",
                Score = 18,
                Severity = ThreatSeverity.High,
                Source = DetectionSource.Heuristic,
                Evidence = string.Join(", ", persistence.Concat(network).Take(8))
            });
        }

        if (injection.Length > 0 && (highEntropy || writableExecutable || packer))
        {
            findings.Add(new Detection
            {
                RuleId = "Heur.PE.PackedLoader",
                Name = "Heur:PE/PackedInjectionLoader",
                Description = "高风险注入 API 与高熵/可写可执行/打包特征组合，常见于加壳加载器。",
                Score = 12,
                Severity = ThreatSeverity.High,
                Source = DetectionSource.Heuristic
            });
        }
    }

    private static HashSet<string> ReadImports(
        PEReader peReader,
        PEHeader peHeader,
        bool isDotNet,
        out List<string> dlls,
        out string? note)
    {
        var imports = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        dlls = new List<string>();
        note = null;
        var directory = peHeader.ImportTableDirectory;
        if (directory.RelativeVirtualAddress <= 0)
        {
            return imports;
        }

        try
        {
            var is64Bit = peHeader.Magic == PEMagic.PE32Plus;
            var thunkSize = is64Bit ? 8 : 4;
            for (var descriptorIndex = 0; descriptorIndex < MaxDlls; descriptorIndex++)
            {
                var descriptor = ReadRva(peReader, directory.RelativeVirtualAddress + descriptorIndex * 20, 20);
                if (descriptor is null)
                {
                    break;
                }

                var nameRva = BitConverter.ToUInt32(descriptor, 12);
                if (nameRva == 0)
                {
                    break;
                }

                var dllNameRaw = ReadRva(peReader, checked((int)nameRva), 256);
                var dllName = dllNameRaw is null ? string.Empty : ReadAsciiZ(dllNameRaw);
                if (!string.IsNullOrWhiteSpace(dllName))
                {
                    dlls.Add(dllName);
                }

                var originalFirstThunk = BitConverter.ToUInt32(descriptor, 0);
                var firstThunk = BitConverter.ToUInt32(descriptor, 16);
                var thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                if (thunkRva == 0)
                {
                    continue;
                }

                for (var importIndex = 0; importIndex < MaxImportsPerDll; importIndex++)
                {
                    var thunkBytes = ReadRva(peReader, checked((int)(thunkRva + importIndex * thunkSize)), thunkSize);
                    if (thunkBytes is null)
                    {
                        break;
                    }

                    var thunk = is64Bit ? BitConverter.ToUInt64(thunkBytes, 0) : BitConverter.ToUInt32(thunkBytes, 0);
                    if (thunk == 0)
                    {
                        break;
                    }

                    var ordinalFlag = is64Bit ? 0x8000000000000000UL : 0x80000000UL;
                    if ((thunk & ordinalFlag) != 0)
                    {
                        continue;
                    }

                    var hintNameRva = checked((int)(thunk & 0x7FFFFFFF));
                    var hintName = ReadRva(peReader, hintNameRva, 2 + 256);
                    if (hintName is null)
                    {
                        continue;
                    }

                    var functionName = ReadAsciiZ(hintName.AsSpan(2));
                    if (!string.IsNullOrWhiteSpace(functionName))
                    {
                        imports.Add(functionName);
                    }
                }
            }
        }
        catch (Exception exception) when (exception is BadImageFormatException or OverflowException or ArgumentException)
        {
            note = "PE 导入表无法完整解析，可能被加壳或故意破坏。";
        }

        if (isDotNet && imports.Count == 0 && dlls.Count == 0)
        {
            note ??= "未解析到 .NET 程序集的导入信息。";
        }

        return imports;
    }

    private static byte[]? ReadRva(PEReader peReader, int relativeVirtualAddress, int length)
    {
        if (relativeVirtualAddress <= 0 || length <= 0)
        {
            return null;
        }

        var block = peReader.GetSectionData(relativeVirtualAddress);
        if (block.Length < length)
        {
            return null;
        }

        return block.GetContent(0, length).ToArray();
    }

    private static string ReadAsciiZ(ReadOnlySpan<byte> bytes)
    {
        var length = bytes.IndexOf((byte)0);
        if (length < 0)
        {
            length = bytes.Length;
        }

        return System.Text.Encoding.ASCII.GetString(bytes[..length]).Trim();
    }

    private static (bool HasCertificate, string? Subject, string? Note, AuthenticodeState State) ReadAuthenticodeInfo(string path, List<string> notes)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, null, null, AuthenticodeState.None);
        }

        try
        {
            var certificate = X509Certificate.CreateFromSignedFile(path);
            using var certificate2 = new X509Certificate2(certificate.GetRawCertData());
            var state = AuthenticodeVerifier.Verify(path);
            var note = state switch
            {
                AuthenticodeState.Valid => "Authenticode 签名校验通过。",
                AuthenticodeState.Invalid => "检测到 Authenticode 证书，但签名校验失败：文件内容被修改或签名被截取/盗用。",
                _ => "检测到 Authenticode 证书（校验状态未知）。"
            };
            notes.Add(note);
            return (true, certificate2.Subject, note, state);
        }
        catch (CryptographicException)
        {
            return (false, null, null, AuthenticodeState.None);
        }
        catch (IOException)
        {
            return (false, null, null, AuthenticodeState.None);
        }
    }

    private static DateTimeOffset? ParseLinkerTimestamp(int secondsSinceUnixEpoch, List<string> notes)
    {
        if (secondsSinceUnixEpoch <= 0)
        {
            return null;
        }

        try
        {
            var timestamp = DateTimeOffset.FromUnixTimeSeconds(secondsSinceUnixEpoch);
            if (timestamp > DateTimeOffset.UtcNow.AddDays(1))
            {
                notes.Add("PE 链接器时间戳晚于当前时间，可能被篡改或由可重复构建工具写入。");
            }

            return timestamp;
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static PeAnalysis CorruptHeaders(string reason)
    {
        return new PeAnalysis(
            null,
            new[]
            {
                new Detection
                {
                    RuleId = "Heur.PE.InvalidHeaders",
                    Name = "Heur:PE/InvalidHeaders",
                    Description = "文件具有 MZ 头，但 PE 结构无效或损坏。",
                    Score = 12,
                    Severity = ThreatSeverity.Low,
                    Source = DetectionSource.Heuristic,
                    Evidence = reason
                }
            },
            new[] { "PE 结构无法完整解析，启发式结果可能不完整。" });
    }
}

public static class EntropyCalculator
{
    public static double Calculate(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (var value in data)
        {
            counts[value]++;
        }

        var entropy = 0.0;
        var length = data.Length;
        foreach (var count in counts)
        {
            if (count == 0)
            {
                continue;
            }

            var probability = (double)count / length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}
