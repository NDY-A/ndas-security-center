param(
    [string]$OutputDir,
    [string]$PythonVersion = '3.12.10',
    [string]$SpeakeasyVersion = '1.5.11',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$installerDir = $PSScriptRoot
$root = Split-Path -Parent $installerDir
if (-not $OutputDir) {
    $OutputDir = Join-Path $root 'dist\sandbox'
}
$cacheDir = Join-Path $installerDir '.cache'
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

$componentJson = Join-Path $OutputDir 'component.json'
$runnerSource = Join-Path $installerDir 'sandbox\ndas_sandbox_runner.py'
$decoyGenerator = Join-Path $installerDir 'sandbox\make_decoys.py'
$stampPath = Join-Path $OutputDir 'build-stamp.json'
if ((Test-Path -LiteralPath $componentJson) -and -not $Force) {
    $stampOk = $false
    if (Test-Path -LiteralPath $stampPath) {
        try {
            $stamp = Get-Content -LiteralPath $stampPath -Raw | ConvertFrom-Json
            $stampOk = ($stamp.pythonVersion -eq $PythonVersion) -and
                       ($stamp.speakeasyVersion -eq $SpeakeasyVersion) -and
                       ($stamp.runnerHash -eq (Get-FileHash -LiteralPath $runnerSource -Algorithm SHA256).Hash) -and
                       ($stamp.decoyHash -eq (Get-FileHash -LiteralPath $decoyGenerator -Algorithm SHA256).Hash)
        }
        catch {
            $stampOk = $false
        }
    }

    if ($stampOk) {
        Write-Host "Sandbox components already prepared: $OutputDir"
        exit 0
    }

    Write-Host 'Sandbox inputs changed; rebuilding components.'
}

if (Test-Path -LiteralPath $OutputDir) {
    Remove-Item -LiteralPath $OutputDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$pyZipName = "python-$PythonVersion-embed-amd64.zip"
$pyZip = Join-Path $cacheDir $pyZipName
$pyUrl = "https://www.python.org/ftp/python/$PythonVersion/$pyZipName"
if (-not (Test-Path -LiteralPath $pyZip)) {
    Write-Host "Downloading $pyUrl"
    Invoke-WebRequest -Uri $pyUrl -OutFile $pyZip -UseBasicParsing
}

$hashFile = "$pyZip.sha256"
$hash = (Get-FileHash -LiteralPath $pyZip -Algorithm SHA256).Hash
if (Test-Path -LiteralPath $hashFile) {
    $recorded = (Get-Content -LiteralPath $hashFile -Raw).Trim()
    if ($recorded -ne $hash) {
        throw "Python embeddable archive hash mismatch: expected $recorded, got $hash"
    }
}
else {
    Set-Content -LiteralPath $hashFile -Value $hash -Encoding ASCII
}

$pythonDir = Join-Path $OutputDir 'python'
Expand-Archive -LiteralPath $pyZip -DestinationPath $pythonDir -Force

$versionParts = $PythonVersion.Split('.')
$zipTag = 'python' + $versionParts[0] + $versionParts[1]
$pthFile = Get-ChildItem -LiteralPath $pythonDir -Filter 'python*._pth' | Select-Object -First 1
if (-not $pthFile) {
    throw "python*._pth not found in embedded distribution."
}
@(
    "$zipTag.zip",
    '.',
    'Lib\site-packages',
    'import site'
) | Set-Content -LiteralPath $pthFile.FullName -Encoding ASCII

$python = Join-Path $pythonDir 'python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw "python.exe not found after extraction."
}

$getPip = Join-Path $cacheDir 'get-pip.py'
if (-not (Test-Path -LiteralPath $getPip)) {
    Write-Host 'Downloading get-pip.py'
    Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile $getPip -UseBasicParsing
}

Write-Host 'Bootstrapping pip in embedded Python'
& $python $getPip --no-warn-script-location --disable-pip-version-check
if ($LASTEXITCODE -ne 0) {
    throw "get-pip.py failed with exit code $LASTEXITCODE"
}

$sitePackages = Join-Path $pythonDir 'Lib\site-packages'
New-Item -ItemType Directory -Force -Path $sitePackages | Out-Null

Write-Host 'Installing setuptools and wheel (needed to build lznt1)'
& $python -m pip install --no-warn-script-location --disable-pip-version-check `
    --target $sitePackages 'setuptools<81' 'wheel'
if ($LASTEXITCODE -ne 0) {
    throw "pip install (setuptools) failed with exit code $LASTEXITCODE"
}

Write-Host "Installing speakeasy-emulator==$SpeakeasyVersion"
& $python -m pip install --no-warn-script-location --disable-pip-version-check `
    --no-build-isolation --target $sitePackages "speakeasy-emulator==$SpeakeasyVersion"
if ($LASTEXITCODE -ne 0) {
    throw "pip install failed with exit code $LASTEXITCODE"
}

& $python $decoyGenerator $sitePackages
if ($LASTEXITCODE -ne 0) {
    throw "decoy generation failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path -LiteralPath $runnerSource)) {
    throw "Runner script not found: $runnerSource"
}
Copy-Item -LiteralPath $runnerSource -Destination (Join-Path $OutputDir 'ndas_sandbox_runner.py') -Force

$licensesDir = Join-Path $OutputDir 'LICENSES'
New-Item -ItemType Directory -Force -Path $licensesDir | Out-Null
$pythonLicense = Join-Path $pythonDir 'LICENSE.txt'
if (Test-Path -LiteralPath $pythonLicense) {
    Copy-Item -LiteralPath $pythonLicense -Destination (Join-Path $licensesDir 'python.txt') -Force
}

Get-ChildItem -LiteralPath $sitePackages -Directory -Filter '*.dist-info' | ForEach-Object {
    $license = Get-ChildItem -LiteralPath $_.FullName -File |
        Where-Object { $_.Name -match '^(LICENSE|COPYING|NOTICE)' } |
        Select-Object -First 1
    if ($license) {
        Copy-Item -LiteralPath $license.FullName -Destination (Join-Path $licensesDir ($_.Name + '-' + $license.Name)) -Force
    }
}

@"
NDAS built-in sandbox third-party components
============================================
- Speakeasy (Mandiant) - MIT License - https://github.com/mandiant/speakeasy
- Unicorn Engine - GPL-2.0 - https://github.com/unicorn-engine/unicorn
  (shipped as the PyPI win_amd64 wheel; source available at the URL above)
- Capstone Engine - BSD 3-Clause - https://github.com/capstone-engine/capstone
- pefile - MIT License - https://github.com/erocarrera/pefile
- pycryptodome - BSD 2-Clause - https://github.com/Legrandin/pycryptodome
- lznt1 - MIT License - https://github.com/you0708/lznt1
- jsonschema - MIT License - https://github.com/python-jsonschema/jsonschema
- Python - PSF License - https://www.python.org/

Full license texts are copied into the LICENSES folder by prepare-sandbox.ps1.
"@ | Set-Content -LiteralPath (Join-Path $licensesDir 'NOTICES-SANDBOX.txt') -Encoding UTF8

$component = [ordered]@{
    engine            = 'speakeasy'
    version           = "speakeasy-$SpeakeasyVersion-py$($versionParts[0])$($versionParts[1])"
    speakeasyVersion  = $SpeakeasyVersion
    pythonVersion     = $PythonVersion
    builtAt           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}
$component | ConvertTo-Json | Set-Content -LiteralPath $componentJson -Encoding UTF8

$stamp = [ordered]@{
    pythonVersion     = $PythonVersion
    speakeasyVersion  = $SpeakeasyVersion
    runnerHash        = (Get-FileHash -LiteralPath $runnerSource -Algorithm SHA256).Hash
    decoyHash         = (Get-FileHash -LiteralPath $decoyGenerator -Algorithm SHA256).Hash
    builtAt           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}
$stamp | ConvertTo-Json | Set-Content -LiteralPath $stampPath -Encoding UTF8

$manifestPath = Join-Path $OutputDir 'sandbox-manifest.sha256'
$lines = New-Object System.Collections.Generic.List[string]
$files = Get-ChildItem -LiteralPath $OutputDir -Recurse -File | Where-Object { $_.FullName -ne $manifestPath }
foreach ($file in $files) {
    $relative = $file.FullName.Substring($OutputDir.Length).TrimStart('\')
    $fileHash = $null
    for ($attempt = 0; $attempt -lt 5 -and -not $fileHash; $attempt++) {
        try {
            $fileHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        catch {
            Start-Sleep -Milliseconds 400
        }
    }

    if (-not $fileHash) {
        Write-Warning "Unreadable file (likely locked by antivirus), skipped in manifest: $relative"
        continue
    }

    $lines.Add("$fileHash  $relative")
}
Set-Content -LiteralPath $manifestPath -Value $lines -Encoding ASCII

$totalBytes = (Get-ChildItem -LiteralPath $OutputDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
Write-Host ("Sandbox components ready: {0} ({1:N1} MB, {2} files)" -f $OutputDir, ($totalBytes / 1MB), $lines.Count)
