param(
    [string]$PythonExe = ".\venv\Scripts\python.exe",
    [string]$OutputDir = "dist\opensearch-agent-installer",
    [ValidateSet("onedir","onefile")]
    [string]$BuildMode = "onedir",
    [switch]$SkipBuildExe
)

$ErrorActionPreference = "Stop"

if (-not $SkipBuildExe) {
    $args = @("-m","PyInstaller","--noconfirm","--name","vant-opensearch-agent","--paths","opensearch_agents","opensearch_agents/agent.py")
    if ($BuildMode -eq "onefile") {
        $args = @("-m","PyInstaller","--noconfirm","--onefile","--name","vant-opensearch-agent","--paths","opensearch_agents","opensearch_agents/agent.py")
    }
    & $PythonExe @args
}

$packageDir = Join-Path $OutputDir "package"
if (Test-Path $packageDir) {
    Remove-Item $packageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $packageDir -Force | Out-Null

if (Test-Path "dist\vant-opensearch-agent\vant-opensearch-agent.exe") {
    Copy-Item "dist\vant-opensearch-agent" (Join-Path $packageDir "vant-opensearch-agent") -Recurse -Force
} elseif (Test-Path "dist\vant-opensearch-agent.exe") {
    Copy-Item "dist\vant-opensearch-agent.exe" (Join-Path $packageDir "vant-opensearch-agent.exe") -Force
} else {
    throw "PyInstaller output not found in dist."
}
Copy-Item "opensearch_agents\installer\Install-OpenSearchAgent.ps1" (Join-Path $packageDir "Install-OpenSearchAgent.ps1") -Force
Copy-Item "opensearch_agents\installer\Uninstall-OpenSearchAgent.ps1" (Join-Path $packageDir "Uninstall-OpenSearchAgent.ps1") -Force
Copy-Item "opensearch_agents\installer\config.yaml" (Join-Path $packageDir "config.yaml") -Force
Copy-Item "opensearch_agents\installer\config.windows-server-ad.yaml" (Join-Path $packageDir "config.windows-server-ad.yaml") -Force
Copy-Item "opensearch_agents\installer\config.windows11-ids.yaml" (Join-Path $packageDir "config.windows11-ids.yaml") -Force

$readmePath = Join-Path $packageDir "README.txt"
@"
VANT OpenSearch Agent Installer

1) Open PowerShell as Administrator.
2) Choose and copy one config:
   - config.windows-server-ad.yaml
   - config.windows11-ids.yaml
   to config.yaml, then edit endpoint/auth/TLS.
3) Run:
   .\Install-OpenSearchAgent.ps1 -RunNow

Verify:
  Get-ScheduledTask -TaskName VANT-OpenSearch-Agent

Uninstall:
  .\Uninstall-OpenSearchAgent.ps1
"@ | Set-Content -Path $readmePath -Encoding UTF8

$zipPath = Join-Path $OutputDir "vant-opensearch-agent-windows.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}
Compress-Archive -Path (Join-Path $packageDir "*") -DestinationPath $zipPath -Force

Write-Host "Installer package created: $zipPath"
