param(
    [string]$Version = "1.2.1",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$slnPath = Join-Path $repoRoot "VTDownloadGuard.sln"
$appProj = Join-Path $repoRoot "src\VTDownloadGuard\VTDownloadGuard.csproj"
$testProj = Join-Path $repoRoot "tests\VTDownloadGuard.Tests\VTDownloadGuard.Tests.csproj"
$issPath = Join-Path $repoRoot "installer\VTDownloadGuard.iss"
$distDir = Join-Path $repoRoot "dist"
$standaloneDir = Join-Path $distDir "publish-standalone"
$portableDir = Join-Path $distDir "publish-portable"
$setupExe = Join-Path $distDir "VTDownloadGuard-$Version-win-x64-Setup.exe"
$portableZip = Join-Path $distDir "VTDownloadGuard-$Version-win-x64-Portable-FrameworkDependent.zip"

function Find-Iscc {
    $cmd = Get-Command iscc -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $candidates = @(
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) { return $candidate }
    }

    throw "Inno Setup 6 (ISCC.exe) was not found. Install it via: winget install JRSoftware.InnoSetup"
}

Write-Host "=== Step 1: Build and Test ==="
dotnet build $slnPath -c Release
if ($LASTEXITCODE -ne 0) { throw "dotnet build failed." }

if (-not $SkipTests) {
    dotnet run --project $testProj -c Release --no-build
    if ($LASTEXITCODE -ne 0) { throw "Automated tests failed." }
}

Write-Host "=== Step 2: Clean dist directory ==="
if (Test-Path $distDir) {
    Remove-Item -Recurse -Force $distDir
}
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

Write-Host "=== Step 3: Publish standalone win-x64 ==="
dotnet publish $appProj -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=false `
    -p:DebugType=none `
    -p:DebugSymbols=false `
    -o $standaloneDir
if ($LASTEXITCODE -ne 0) { throw "Standalone publish failed." }

Write-Host "=== Step 4: Compile Windows installer ==="
$iscc = Find-Iscc
& $iscc $issPath
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }
if (-not (Test-Path $setupExe)) { throw "Expected installer missing: $setupExe" }

Write-Host "=== Step 5: Publish portable framework-dependent zip ==="
dotnet publish $appProj -c Release -r win-x64 --no-self-contained `
    -p:PublishSingleFile=false `
    -p:DebugType=none `
    -p:DebugSymbols=false `
    -o $portableDir
if ($LASTEXITCODE -ne 0) { throw "Portable publish failed." }

Compress-Archive -Path (Join-Path $portableDir "*") -DestinationPath $portableZip -CompressionLevel Optimal -Force
if (-not (Test-Path $portableZip)) { throw "Expected portable zip missing: $portableZip" }

Write-Host ""
Write-Host "=== Release Artifacts ==="
foreach ($artifact in @($setupExe, $portableZip)) {
    $fi = Get-Item $artifact
    $hash = (Get-FileHash $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    $mb = [Math]::Round($fi.Length / 1MB, 2)
    Write-Host ("{0} ({1} MB, {2} bytes)" -f $fi.Name, $mb, $fi.Length)
    Write-Host ("  SHA256: {0}" -f $hash)
}
