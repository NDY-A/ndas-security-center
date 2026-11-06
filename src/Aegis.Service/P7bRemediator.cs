using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Aegis.Service;

public enum P7bPolicyVerdict
{
    Trusted,
    Suspicious,
    Unreadable
}

public sealed record P7bInspection(P7bPolicyVerdict Verdict, string Detail);

public static class P7bRemediator
{
    private const long MaxPolicyBytes = 16L * 1024 * 1024;
    private const string DisableMarker = "Enabled:Disabled";

    public static P7bInspection Inspect(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return new P7bInspection(P7bPolicyVerdict.Unreadable, "策略文件不存在");
            }

            if (info.Length == 0)
            {
                return new P7bInspection(P7bPolicyVerdict.Suspicious, "策略文件为空");
            }

            if (info.Length > MaxPolicyBytes)
            {
                return new P7bInspection(P7bPolicyVerdict.Unreadable, "策略文件超过检查大小上限");
            }

            var bytes = File.ReadAllBytes(path);
            var hasDisableMarker = ContainsDisableMarker(bytes);

            SignedCms cms;
            try
            {
                cms = new SignedCms();
                cms.Decode(bytes);
            }
            catch (Exception exception)
            {
                return new P7bInspection(P7bPolicyVerdict.Suspicious,
                    "不是有效的 PKCS#7 策略文件（" + exception.GetType().Name + "）");
            }

            var signatureValid = false;
            try
            {
                cms.CheckSignature(verifySignatureOnly: true);
                signatureValid = true;
            }
            catch
            {
                signatureValid = false;
            }

            var chainTrusted = signatureValid && SignerChainTrusted(cms);

            if (hasDisableMarker)
            {
                return new P7bInspection(P7bPolicyVerdict.Suspicious,
                    chainTrusted ? "策略包含 Enabled:Disabled（尝试禁用 WDAC）" : "策略包含 Enabled:Disabled 且签名不可信");
            }

            if (chainTrusted)
            {
                return new P7bInspection(P7bPolicyVerdict.Trusted, "策略签名有效且证书链受信任");
            }

            return new P7bInspection(P7bPolicyVerdict.Suspicious, "策略签名无效或签名证书不受信任");
        }
        catch (Exception exception)
        {
            return new P7bInspection(P7bPolicyVerdict.Unreadable, "无法读取策略文件：" + exception.Message);
        }
    }

    public static bool TryBackupAndDelete(string path, string dataRoot, out string detail)
    {
        detail = string.Empty;
        var inspection = Inspect(path);
        if (inspection.Verdict == P7bPolicyVerdict.Trusted)
        {
            detail = "策略可信，未删除：" + inspection.Detail;
            return false;
        }

        if (inspection.Verdict == P7bPolicyVerdict.Unreadable)
        {
            detail = "未删除：" + inspection.Detail;
            return false;
        }

        try
        {
            var backupDirectory = Path.Combine(dataRoot, "backup", "p7b");
            Directory.CreateDirectory(backupDirectory);
            var backupPath = Path.Combine(backupDirectory,
                $"{DateTimeOffset.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}-{Path.GetFileName(path)}");
            File.Copy(path, backupPath, overwrite: false);
            File.Delete(path);
            detail = $"{inspection.Detail}；已备份到 {backupPath} 并删除原文件";
            return true;
        }
        catch (Exception exception)
        {
            detail = "备份或删除失败：" + exception.Message;
            return false;
        }
    }

    private static bool SignerChainTrusted(SignedCms cms)
    {
        foreach (var signer in cms.SignerInfos)
        {
            var certificate = signer.Certificate;
            if (certificate is null)
            {
                continue;
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            try
            {
                if (chain.Build(certificate))
                {
                    return true;
                }

                // Windows policy files are signed once and keep working after the signing
                // certificate expires; the chain is only untrusted if it is invalid for a
                // reason other than time.
                if (chain.ChainStatus.Length > 0 &&
                    chain.ChainStatus.All(status => status.Status is
                        X509ChainStatusFlags.NotTimeValid or
                        X509ChainStatusFlags.RevocationStatusUnknown or
                        X509ChainStatusFlags.OfflineRevocation))
                {
                    return true;
                }
            }
            catch
            {
                // Try the next signer.
            }
        }

        return false;
    }

    private static bool ContainsDisableMarker(byte[] bytes)
    {
        try
        {
            if (Encoding.Latin1.GetString(bytes).Contains(DisableMarker, StringComparison.Ordinal))
            {
                return true;
            }

            return Encoding.Unicode.GetString(bytes).Contains(DisableMarker, StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }
}
