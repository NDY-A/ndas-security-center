param(
    [string]$Configuration = 'Release',
    [string]$Version = '0.0.7.0',
    [string]$DisplayVersion = 'rs_p0.0.7.0a',
    [string]$PublishFolderName = 'publish',
    [switch]$SkipSandboxPrepare
)

$ErrorActionPreference = 'Stop'

$installerDir = $PSScriptRoot
$root = Split-Path -Parent $installerDir
$publishDir = Join-Path $root "dist\$PublishFolderName"
$servicePublishDir = Join-Path $root 'dist\service'
$sandboxDir = Join-Path $root 'dist\sandbox'
$msiPath = Join-Path $root "dist\NDAS-$DisplayVersion-win-x64.msi"

$guardDir = Join-Path $root 'dist\guard'

$nativeBuild = Join-Path $root 'native\AegisMl\build.ps1'
if (Test-Path -LiteralPath $nativeBuild) {
    & $nativeBuild -Config $Configuration
}

$guardBuild = Join-Path $root 'native\NdasGuard\build.ps1'
if (Test-Path -LiteralPath $guardBuild) {
    & $guardBuild -Config $Configuration
    New-Item -ItemType Directory -Force -Path $guardDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'native\NdasGuard\build\NdasGuard.exe') -Destination $guardDir -Force
}

if (-not $SkipSandboxPrepare) {
    & (Join-Path $installerDir 'prepare-sandbox.ps1') -OutputDir $sandboxDir
    if ($LASTEXITCODE -ne 0) {
        throw "prepare-sandbox.ps1 failed with exit code $LASTEXITCODE"
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $sandboxDir 'component.json'))) {
    throw "Sandbox components are missing at $sandboxDir. Run prepare-sandbox.ps1 first."
}

if (Test-Path -LiteralPath $publishDir) {
    Remove-Item -LiteralPath $publishDir -Recurse -Force
}

if (Test-Path -LiteralPath $servicePublishDir) {
    Remove-Item -LiteralPath $servicePublishDir -Recurse -Force
}

dotnet publish (Join-Path $root 'src\Aegis.App\Aegis.App.csproj') `
    -c $Configuration -p:Platform=x64 -r win-x64 --self-contained true `
    -o $publishDir --nologo
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

dotnet publish (Join-Path $root 'src\Aegis.Service\Aegis.Service.csproj') `
    -c $Configuration -p:Platform=x64 -r win-x64 --self-contained true `
    -o $servicePublishDir --nologo
if ($LASTEXITCODE -ne 0) {
    throw "service publish failed with exit code $LASTEXITCODE"
}

Get-ChildItem -LiteralPath $publishDir -Filter '*.pdb' -Recurse -File | Remove-Item -Force
Get-ChildItem -LiteralPath $servicePublishDir -Filter '*.pdb' -Recurse -File | Remove-Item -Force

$licenseRtf = Join-Path $installerDir 'license.rtf'

wix build (Join-Path $installerDir 'NDAS.wxs') `
    -arch x64 -ext WixToolset.UI.wixext `
    -d "Version=$Version" `
    -d "PublishDir=$publishDir" `
    -d "ServicePublishDir=$servicePublishDir" `
    -d "SandboxDir=$sandboxDir" `
    -d "GuardDir=$guardDir" `
    -d "LicenseRtf=$licenseRtf" `
    -pdbtype none `
    -o $msiPath
if ($LASTEXITCODE -ne 0) {
    throw "wix build failed with exit code $LASTEXITCODE"
}

Write-Host "MSI: $msiPath"
