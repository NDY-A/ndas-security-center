param(
    [string]$Configuration = 'Release',
    [string]$Version = '0.0.2.0',
    [string]$DisplayVersion = 'rs_p0.0.2.0a',
    [string]$PublishFolderName = 'publish'
)

$ErrorActionPreference = 'Stop'

$installerDir = $PSScriptRoot
$root = Split-Path -Parent $installerDir
$publishDir = Join-Path $root "dist\$PublishFolderName"
$servicePublishDir = Join-Path $root 'dist\service'
$msiPath = Join-Path $root "dist\NDAS-$DisplayVersion-win-x64.msi"

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
    -d "LicenseRtf=$licenseRtf" `
    -pdbtype none `
    -o $msiPath
if ($LASTEXITCODE -ne 0) {
    throw "wix build failed with exit code $LASTEXITCODE"
}

Write-Host "MSI: $msiPath"
