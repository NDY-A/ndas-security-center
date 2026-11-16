param(
    [string]$OutputDir = '',
    [string]$AgentSourceDir = '',
    [string]$Version = '0.0.11.0a',
    [switch]$SkipModel
)

$ErrorActionPreference = 'Stop'

$installerDir = $PSScriptRoot
$root = Split-Path -Parent $installerDir
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $root 'dist\agent'
}

if ([string]::IsNullOrWhiteSpace($AgentSourceDir)) {
    $AgentSourceDir = Join-Path $root 'tools\security-agent'
}

Write-Host "Preparing decision agent component -> $OutputDir"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$files = @(
    'agent_daemon.py',
    'agent_policy.py',
    'agent_schema.py',
    'agent_actions.py',
    'agent_model_runtime.py'
)
foreach ($file in $files) {
    $source = Join-Path $AgentSourceDir $file
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Agent file missing: $source"
    }

    Copy-Item -LiteralPath $source -Destination $OutputDir -Force
}

$modelSource = Join-Path $AgentSourceDir 'agent-model.onnx'
if (Test-Path -LiteralPath $modelSource) {
    Copy-Item -LiteralPath $modelSource -Destination (Join-Path $OutputDir 'agent-model.onnx') -Force
}
elseif (-not $SkipModel) {
    throw 'agent-model.onnx missing; run make_agent_data.py, train_agent_model.py and export_agent_onnx.py first (or pass -SkipModel for rules-only).'
}

$scriptModel = Join-Path $root 'ml\model\script-ngram\script-ngram.onnx'
if (Test-Path -LiteralPath $scriptModel) {
    Copy-Item -LiteralPath $scriptModel -Destination (Join-Path $OutputDir 'script-ngram.onnx') -Force
}

$modelName = $null
if (Test-Path -LiteralPath (Join-Path $OutputDir 'agent-model.onnx')) {
    $modelName = 'agent-model.onnx'
}

$component = [ordered]@{
    engine          = 'ndas-agent'
    version         = $Version
    protocolVersion = 1
    pythonRuntime   = '..\Sandbox\python\python.exe'
    model           = $modelName
    builtAt         = (Get-Date).ToUniversalTime().ToString('o')
}
$component | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDir 'component.json') -Encoding UTF8

$manifest = foreach ($file in Get-ChildItem -LiteralPath $OutputDir -File -Recurse) {
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash *$($file.Name)"
}
$manifest | Set-Content -LiteralPath (Join-Path $OutputDir 'agent-manifest.sha256') -Encoding UTF8

Write-Host ("Agent component ready: {0} ({1} files)" -f $OutputDir, @($manifest).Count)
