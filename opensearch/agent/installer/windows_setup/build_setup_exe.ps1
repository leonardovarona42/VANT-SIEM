param(
    [string]$PythonExe = "C:\Users\leonardo.varona\3D Objects\develop\venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"

$pkgZip = "opensearch\agent\installer\windows_setup\package.zip"
if (Test-Path $pkgZip) {
    Remove-Item $pkgZip -Force
}

Compress-Archive -Path "dist\opensearch-agent-installer\package\*" -DestinationPath $pkgZip -Force

$pkgZipAbs = (Resolve-Path $pkgZip).Path
$bootstrapAbs = (Resolve-Path "opensearch\agent\installer\windows_setup\setup_bootstrap.py").Path

& $PythonExe -m PyInstaller `
  --noconfirm `
  --onefile `
  --name setup `
  --distpath "dist\opensearch-agent-installer" `
  --workpath "build\setup-bootstrap" `
  --specpath "build\setup-bootstrap" `
  --add-data "$pkgZipAbs;." `
  "$bootstrapAbs"

Write-Host "setup.exe created in dist\opensearch-agent-installer\setup.exe"
