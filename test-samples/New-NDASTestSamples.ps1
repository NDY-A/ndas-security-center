# 生成 NDAS 无害测试样本（请在虚拟机中运行）
# 输出:
#   eicar.com                -> 触发 Multi_EICAR（YARA）      severity 1
#   yara-blindspot.txt       -> 触发 Multi_AttackSimulation_Blindspot  severity 1
#   yara-generic-threat.txt  -> 触发 Multi_Generic_Threat      severity 50
# 全部为无害标记，不含可执行恶意代码。
param(
    [string]$OutDir = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# EICAR 标准测试串按片段拼接，避免脚本文件本身命中文档扫描
$eicar = (@('X5O!P%@AP[4\PZ', 'X54(P^)7CC)7}$EICA', 'R-STANDARD-ANTIVIRUS-TEST-FILE!', '$H+H*') -join '')

$samples = @(
    @{ Name = 'eicar.com';               Bytes = [Text.Encoding]::ASCII.GetBytes($eicar) }
    @{ Name = 'yara-blindspot.txt';      Text  = '\\.\pipe\blindspot-%d.' }
    @{ Name = 'yara-generic-threat.txt'; Text  = '&*struct { EntrySalt []uint8; Len int }' }
)

$rows = foreach ($sample in $samples) {
    $path = Join-Path $OutDir $sample.Name
    try {
        if ($sample.ContainsKey('Bytes')) {
            [IO.File]::WriteAllBytes($path, $sample.Bytes)
        }
        else {
            [IO.File]::WriteAllText($path, $sample.Text, [Text.Encoding]::ASCII)
        }

        $hash = try { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } catch { '<读取被拦截>' }
        [pscustomobject]@{
            文件   = $sample.Name
            大小   = (Get-Item -LiteralPath $path).Length
            SHA256 = $hash
            状态   = '已生成'
        }
    }
    catch {
        [pscustomobject]@{
            文件   = $sample.Name
            大小   = $null
            SHA256 = $null
            状态   = '写入失败: ' + $_.Exception.Message
        }
    }
}

$rows | Format-Table -AutoSize
