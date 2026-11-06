using System.Text.RegularExpressions;
using Aegis.Core.Models;

namespace Aegis.Core.Heuristics;

public sealed class TextIndicatorRule
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required int Score { get; init; }
    public required ThreatSeverity Severity { get; init; }
    public required Regex Pattern { get; init; }
    public IReadOnlySet<FileKind>? Kinds { get; init; }
}

public static class TextIndicatorRules
{
    private static readonly RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.Singleline;

    private static readonly HashSet<FileKind> DocumentKinds = new()
    {
        FileKind.MacroDocument, FileKind.Document
    };

    private static readonly HashSet<FileKind> ScriptKinds = new()
    {
        FileKind.Script, FileKind.MacroDocument, FileKind.Document, FileKind.Shortcut
    };

    public static IReadOnlyList<TextIndicatorRule> All { get; } = new[]
    {
        Rule(
            "Heur.Script.EncodedPowerShell",
            "Heur:Script/EncodedPowerShell",
            "检测到 PowerShell 编码命令参数，常用于隐藏脚本内容。",
            30,
            ThreatSeverity.High,
            @"\b(?:powershell|pwsh)(?:\.exe)?\b.{0,200}?-(?:e|en|enc|enco|encodedcommand)\b"),
        Rule(
            "Heur.Script.DownloadCradle",
            "Heur:Script/DownloadCradle",
            "脚本包含从网络下载内容或缓存下载的常见语句。",
            22,
            ThreatSeverity.High,
            @"(?:downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|start-bitstransfer|bitsadmin(?:\.exe)?\s+/transfer|certutil(?:\.exe)?\s+-urlcache)"),
        Rule(
            "Heur.Script.InvokeExpression",
            "Heur:Script/InvokeExpression",
            "使用 Invoke-Expression/IEX 动态执行字符串。",
            14,
            ThreatSeverity.Medium,
            @"\b(?:iex|invoke-expression)\b\s*[\(\s]"),
        Rule(
            "Heur.Script.HiddenExecution",
            "Heur:Script/HiddenExecution",
            "包含隐藏窗口、WScript.Shell 或远程 HTA 执行特征。",
            14,
            ThreatSeverity.Medium,
            @"(?:-windowstyle\s+hidden|-w\s+hidden|wscript\.shell|mshta(?:\.exe)?\s+https?://)"),
        Rule(
            "Heur.Script.DefenderTamper",
            "Heur:Script/SecurityTamper",
            "包含关闭 AMSI、修改 Defender 排除项或防护配置的语句。",
            35,
            ThreatSeverity.High,
            @"(?:add-mppreference|set-mppreference|amsiinitfailed|amsiutils|disableantispyware|disablebehaviormonitoring|exclusionpath|disablerealtimemonitoring)"),
        Rule(
            "Heur.Script.ShadowCopyDeletion",
            "Heur:Script/ShadowCopyDeletion",
            "包含删除卷影副本或关闭系统恢复的勒索软件常用命令。",
            45,
            ThreatSeverity.Critical,
            @"(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)|bcdedit[^\r\n]{0,100}recoveryenabled\s+no)"),
        Rule(
            "Heur.Script.CredentialDump",
            "Heur:Script/CredentialDump",
            "出现 Mimikatz、LSASS 转储或 comsvcs MiniDump 等凭据窃取特征。",
            55,
            ThreatSeverity.Critical,
            @"(?:mimikatz|sekurlsa|lsass(?:\.exe)?[^\r\n]{0,80}(?:dump|comsvcs)|comsvcs\.dll[^\r\n]{0,40}minidump|procdump[^\r\n]{0,80}lsass)"),
        Rule(
            "Heur.Script.ProcessInjection",
            "Heur:Script/ProcessInjection",
            "脚本中出现跨进程内存写入或远程线程 API。",
            25,
            ThreatSeverity.High,
            @"(?:virtualallocex[^\r\n]{0,180}writeprocessmemory|createremotethread|ntcreatethreadex)"),
        Rule(
            "Heur.Script.Persistence",
            "Heur:Script/Persistence",
            "包含计划任务或 Run 注册表自启动持久化特征。",
            16,
            ThreatSeverity.Medium,
            @"(?:schtasks(?:\.exe)?\s+/create|currentversion\\run\b|new-scheduledtask|reg\s+add[^\r\n]{0,180}\\(?:run|runonce)\b)"),
        Rule(
            "Heur.Script.LongBase64",
            "Heur:Script/EncodedBlob",
            "包含很长的 Base64 块，可能用于隐藏载荷。",
            10,
            ThreatSeverity.Low,
            @"[a-z0-9+/]{240,}={0,2}"),
        Rule(
            "Heur.Script.MacroAutoExec",
            "Heur:Document/MacroAutoExec",
            "宏自动执行入口与 Shell/CreateObject/下载能力组合出现。",
            28,
            ThreatSeverity.High,
            @"(?:autoopen|document_open|workbook_open).{0,320}(?:shell|createobject|urldownloadtofile|powershell)",
            DocumentKinds),
        Rule(
            "Heur.Script.RemoteHta",
            "Heur:Script/RemoteHta",
            "mshta 直接执行远程脚本或脚本协议 URL。",
            32,
            ThreatSeverity.High,
            @"mshta(?:\.exe)?\s+(?:https?://|vbscript:|javascript:)"),
        Rule(
            "Heur.Script.Rundll32Remote",
            "Heur:Script/Rundll32Remote",
            "rundll32 被用于执行远程或脚本协议 URL。",
            35,
            ThreatSeverity.High,
            @"rundll32(?:\.exe)?\s+(?:https?://|javascript:)"),
        Rule(
            "Heur.Script.WmiExecution",
            "Heur:Script/WmiExecution",
            "包含通过 WMI/WMIC 创建进程的远程执行特征。",
            18,
            ThreatSeverity.Medium,
            @"(?:wmic[^\r\n]{0,140}(?:process\s+call\s+create|/node:)|win32_process[^\r\n]{0,100}create)"),
        Rule(
            "Heur.Script.RansomNote",
            "Heur:Script/RansomNote",
            "包含勒索说明、加密文件或赎金相关文本。",
            22,
            ThreatSeverity.High,
            @"(?:your files (?:have been|are) encrypted|bitcoin[^\r\n]{0,100}(?:ransom|decrypt)|all your files[^\r\n]{0,80}encrypted)")
    };

    private static TextIndicatorRule Rule(
        string id,
        string name,
        string description,
        int score,
        ThreatSeverity severity,
        string pattern,
        IReadOnlySet<FileKind>? kinds = null)
    {
        return new TextIndicatorRule
        {
            Id = id,
            Name = name,
            Description = description,
            Score = score,
            Severity = severity,
            Pattern = new Regex(pattern, Options),
            Kinds = kinds
        };
    }
}
