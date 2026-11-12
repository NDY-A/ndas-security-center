using Aegis.Core.Models;

namespace Aegis.Sandbox;

public static class SandboxTrigger
{
    public const double ExecutableSectionEntropyThreshold = 7.2;
    public const double FileEntropyThreshold = 7.5;

    public static bool HasHighEntropy(PeFileInfo? peInfo)
    {
        if (peInfo is null)
        {
            return false;
        }

        if (peInfo.FileEntropy is double fileEntropy && fileEntropy >= FileEntropyThreshold)
        {
            return true;
        }

        return peInfo.Sections.Any(section =>
            section.IsExecutable && section.Entropy > ExecutableSectionEntropyThreshold);
    }

    public static bool ShouldSubmit(FileScanResult result, SandboxOptions options, bool isSystemPath, out string reason)
    {
        reason = string.Empty;
        if (!options.Enabled)
        {
            reason = "沙箱分析未启用";
            return false;
        }

        if (isSystemPath)
        {
            reason = "系统软件目录只按强证据处置，不送沙箱";
            return false;
        }

        if (result.Kind != FileKind.PortableExecutable)
        {
            reason = "不是 PE 文件";
            return false;
        }

        if (result.Verdict is ThreatVerdict.Malicious or ThreatVerdict.Pua)
        {
            reason = "已有较高风险判定，不再送沙箱";
            return false;
        }

        if (result.PeInfo is null)
        {
            reason = "缺少 PE 结构信息";
            return false;
        }

        if (result.PeInfo.IsDotNet)
        {
            reason = "Speakeasy 不支持 .NET 程序集";
            return false;
        }

        if (HasDecisiveEvidence(result))
        {
            reason = "已有哈希/路径/YARA/云强证据";
            return false;
        }

        if (result.Size < options.MinFileSizeBytes || result.Size > options.MaxFileSizeBytes)
        {
            reason = "文件大小不在沙箱分析范围内";
            return false;
        }

        if (!HasHighEntropy(result.PeInfo))
        {
            reason = "未达到高熵阈值";
            return false;
        }

        reason = "高熵 PE，无强证据，送沙箱分析";
        return true;
    }

    public static bool HasDecisiveEvidence(FileScanResult result)
    {
        foreach (var detection in result.Detections)
        {
            if (detection.Source is DetectionSource.Hash or DetectionSource.PathIoc or
                DetectionSource.BuiltInTest or DetectionSource.Yara)
            {
                return true;
            }

            if (detection.Source == DetectionSource.Cloud && detection.Score >= 90)
            {
                return true;
            }
        }

        return false;
    }
}
