param(
    [string]$InstallDir = "$env:ProgramFiles\VANT\OpenSearchAgent",
    [string]$TaskName = "VANT-OpenSearch-Agent",
    [switch]$RunNow,
    [switch]$UserMode
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($UserMode) {
    if ($InstallDir -eq "$env:ProgramFiles\VANT\OpenSearchAgent") {
        $InstallDir = "$env:LOCALAPPDATA\VANT\OpenSearchAgent"
    }
}

if (-not $UserMode -and -not (Test-Admin)) {
    throw "Run PowerShell as Administrator."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exeSource = Join-Path $scriptDir "vant-opensearch-agent.exe"
$traySource = Join-Path $scriptDir "vant-opensearch-agent-tray.exe"
$dirSource = Join-Path $scriptDir "vant-opensearch-agent"
$cfgSource = Join-Path $scriptDir "config.yaml"

if (-not (Test-Path $exeSource) -and -not (Test-Path (Join-Path $dirSource "vant-opensearch-agent.exe"))) {
    throw "Agent binary not found in package."
}

# Stop existing task before replacing binaries to avoid locked files.
try {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
} catch {}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $InstallDir "logs") -Force | Out-Null

if (Test-Path (Join-Path $dirSource "vant-opensearch-agent.exe")) {
    $agentInstallDir = Join-Path $InstallDir "agent"
    if (Test-Path $agentInstallDir) {
        Remove-Item $agentInstallDir -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $agentInstallDir) {
            Start-Sleep -Seconds 2
            Remove-Item $agentInstallDir -Recurse -Force
        }
    }
    Copy-Item $dirSource $agentInstallDir -Recurse -Force
    $exePath = Join-Path $agentInstallDir "vant-opensearch-agent.exe"
} else {
    Copy-Item $exeSource (Join-Path $InstallDir "vant-opensearch-agent.exe") -Force
    $exePath = Join-Path $InstallDir "vant-opensearch-agent.exe"
}
if (Test-Path $traySource) {
    Copy-Item $traySource (Join-Path $InstallDir "vant-opensearch-agent-tray.exe") -Force
}
if (Test-Path $cfgSource) {
    Copy-Item $cfgSource (Join-Path $InstallDir "config.yaml") -Force
}
if (Test-Path (Join-Path $scriptDir "staticfiles")) {
    Copy-Item (Join-Path $scriptDir "staticfiles") (Join-Path $InstallDir "staticfiles") -Recurse -Force
}

$cfgPath = Join-Path $InstallDir "config.yaml"
$arg = "--config `"$cfgPath`""
$trayExe = Join-Path $InstallDir "vant-opensearch-agent-tray.exe"
$trayArg = "--config `"$cfgPath`" --monitor-only"
$runKeyPath = if ($UserMode) {
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
} else {
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
}
$runValueName = "VANTOpenSearchAgentTray"

$action = New-ScheduledTaskAction -Execute $exePath -Argument $arg
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
if ($UserMode) {
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
} else {
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

$startupDir = if ($UserMode) {
    [Environment]::GetFolderPath("Startup")
} else {
    [Environment]::GetFolderPath("CommonStartup")
}

if (Test-Path $trayExe) {
    $shortcutPath = Join-Path $startupDir "VANT-OpenSearch-Agent Tray.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $trayExe
    $shortcut.Arguments = $trayArg
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.IconLocation = "$trayExe,0"
    $shortcut.Description = "VANT-SIEM Agent tray"
    $shortcut.Save()
    New-Item -Path $runKeyPath -Force | Out-Null
    Set-ItemProperty -Path $runKeyPath -Name $runValueName -Value "`"$trayExe`" $trayArg" -Force
}

if ($RunNow) {
    Start-ScheduledTask -TaskName $TaskName
    if ((Test-Path $trayExe) -and [Environment]::UserInteractive) {
        Start-Process -FilePath $trayExe -ArgumentList $trayArg -WorkingDirectory $InstallDir
    }
}

Write-Host "Installed OpenSearch agent."
Write-Host "InstallDir: $InstallDir"
Write-Host "TaskName: $TaskName"
Write-Host "Mode: $(if ($UserMode) { 'UserMode' } else { 'SystemMode' })"
Write-Host "Edit config: $cfgPath"
