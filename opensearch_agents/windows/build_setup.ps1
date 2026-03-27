param(
    [string]$PythonExe = "C:\Users\leonardo.varona\3D Objects\develop\venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"

function Assert-BuildDependency {
    param(
        [string]$ModuleName,
        [string]$PipName = $ModuleName
    )

    & $PythonExe -c "import $ModuleName" 2>$null
    if ($LASTEXITCODE -eq 0) {
        return
    }

    Write-Host "Instalando dependencia de build faltante: $PipName"
    & $PythonExe -m pip install $PipName
    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo instalar la dependencia requerida: $PipName"
    }
}

Assert-BuildDependency -ModuleName "PyInstaller"
Assert-BuildDependency -ModuleName "requests"
Assert-BuildDependency -ModuleName "yaml" -PipName "pyyaml"
Assert-BuildDependency -ModuleName "PyQt6"

$repoRoot = (Resolve-Path ".").Path
$windowsDir = Join-Path $repoRoot "opensearch_agents\windows"
$buildRoot = Join-Path $env:TEMP ("vant-opensearch-build-" + (Get-Date -Format "yyyyMMddHHmmss"))
$agentWork = Join-Path $buildRoot "agent-work"
$agentSpec = Join-Path $buildRoot "agent-spec"
$agentDist = Join-Path $buildRoot "agent-dist"
$setupWork = Join-Path $buildRoot "setup-work"
$setupSpec = Join-Path $buildRoot "setup-spec"
$trayWork = Join-Path $buildRoot "tray-work"
$traySpec = Join-Path $buildRoot "tray-spec"
$packageDir = Join-Path $windowsDir "package"
$configsDir = Join-Path $windowsDir "configs"
$outputExe = Join-Path $windowsDir "opensearch_agent_setup.exe"

if (Test-Path $buildRoot) {
    Remove-Item $buildRoot -Recurse -Force
}

if (Test-Path $packageDir) {
    Remove-Item $packageDir -Recurse -Force
}

foreach ($path in @($agentWork, $agentSpec, $agentDist, $trayWork, $traySpec, $setupWork, $setupSpec, $packageDir)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

if (Test-Path $outputExe) {
    Remove-Item $outputExe -Force
}

& $PythonExe -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --name "vant-opensearch-agent" `
  --paths "opensearch_agents" `
  --hidden-import "yaml" `
  --hidden-import "requests" `
  --distpath $agentDist `
  --workpath $agentWork `
  --specpath $agentSpec `
  "opensearch_agents\agent.py"

$agentExe = Join-Path $agentDist "vant-opensearch-agent.exe"
if (-not (Test-Path $agentExe)) {
    throw "No se pudo generar vant-opensearch-agent.exe"
}

& $PythonExe -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --windowed `
  --name "vant-opensearch-agent-tray" `
  --paths "opensearch_agents" `
  --hidden-import "agent" `
  --hidden-import "PyQt6.sip" `
  --hidden-import "PyQt6.QtCore" `
  --hidden-import "PyQt6.QtGui" `
  --hidden-import "PyQt6.QtWidgets" `
  --hidden-import "requests" `
  --hidden-import "yaml" `
  --distpath $agentDist `
  --workpath $trayWork `
  --specpath $traySpec `
  "opensearch_agents\agent_tray.py"

if ($LASTEXITCODE -ne 0) {
    throw "Fallo PyInstaller al compilar vant-opensearch-agent-tray.exe"
}

$trayExe = Join-Path $agentDist "vant-opensearch-agent-tray.exe"
if (-not (Test-Path $trayExe)) {
    throw "No se pudo generar vant-opensearch-agent-tray.exe"
}

Copy-Item $agentExe (Join-Path $packageDir "vant-opensearch-agent.exe") -Force
Copy-Item $trayExe (Join-Path $packageDir "vant-opensearch-agent-tray.exe") -Force
Copy-Item (Join-Path $windowsDir "Install-OpenSearchAgent.ps1") (Join-Path $packageDir "Install-OpenSearchAgent.ps1") -Force
Copy-Item (Join-Path $windowsDir "Uninstall-OpenSearchAgent.ps1") (Join-Path $packageDir "Uninstall-OpenSearchAgent.ps1") -Force
Copy-Item (Join-Path $configsDir "config.yaml") (Join-Path $packageDir "config.yaml") -Force
Copy-Item (Join-Path $configsDir "config.windows-server-ad.yaml") (Join-Path $packageDir "config.windows-server-ad.yaml") -Force
Copy-Item (Join-Path $configsDir "config.windows11-ids.yaml") (Join-Path $packageDir "config.windows11-ids.yaml") -Force

$bootstrapKey = Join-Path $windowsDir "bootstrap.key"
if (Test-Path $bootstrapKey) {
    Copy-Item $bootstrapKey (Join-Path $packageDir "bootstrap.key") -Force
}

$packageAbs = (Resolve-Path $packageDir).Path
$logoAbs = (Resolve-Path "staticfiles\img\logo.png").Path
$packageStaticDir = Join-Path $packageDir "staticfiles\img"
New-Item -ItemType Directory -Path $packageStaticDir -Force | Out-Null
Copy-Item $logoAbs (Join-Path $packageStaticDir "logo.png") -Force

& $PythonExe -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --windowed `
  --name "opensearch_agent_setup" `
  --hidden-import "PyQt6.sip" `
  --hidden-import "PyQt6.QtCore" `
  --hidden-import "PyQt6.QtGui" `
  --hidden-import "PyQt6.QtWidgets" `
  --hidden-import "requests" `
  --hidden-import "yaml" `
  --distpath $windowsDir `
  --workpath $setupWork `
  --specpath $setupSpec `
  --add-data "${packageAbs};package" `
  --add-data "${logoAbs};staticfiles\img" `
  "opensearch_agents\windows\agent_setup_ui.py"

if (-not (Test-Path $outputExe)) {
    throw "No se pudo generar opensearch_agent_setup.exe"
}

Write-Host "Windows GUI setup listo en: $outputExe"
