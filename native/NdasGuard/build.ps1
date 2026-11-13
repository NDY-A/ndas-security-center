param(
    [string]$Config = "Release"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$buildDir = Join-Path $root "build"
$vsRoot = "G:\Program Files\Microsoft Visual Studio"
$vcvars = Join-Path $vsRoot "VC\Auxiliary\Build\vcvars64.bat"
$cmake = Join-Path $vsRoot "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$ninja = Join-Path $vsRoot "Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"

foreach ($tool in @($vcvars, $cmake, $ninja)) {
    if (-not (Test-Path $tool)) { throw "missing build tool: $tool" }
}

$command = "call `"$vcvars`" >nul && `"$cmake`" -S `"$root`" -B `"$buildDir`" -G Ninja -DCMAKE_BUILD_TYPE=$Config -DCMAKE_MAKE_PROGRAM=`"$ninja`" && `"$cmake`" --build `"$buildDir`""
cmd /c $command
if ($LASTEXITCODE -ne 0) { throw "build failed" }

Write-Host "build done: $buildDir"
Get-ChildItem $buildDir -Filter "NdasGuard.exe" | Format-Table Name, Length
