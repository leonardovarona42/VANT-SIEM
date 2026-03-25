param(
    [string]$InstallDir = "$env:ProgramFiles\VANT\OpenSearchAgent",
    [string]$TaskName = "VANT-OpenSearch-Agent",
    [switch]$KeepFiles,
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

try {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
} catch {}

try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
} catch {}

$startupDir = if ($UserMode) {
    [Environment]::GetFolderPath("Startup")
} else {
    [Environment]::GetFolderPath("CommonStartup")
}
$shortcutPath = Join-Path $startupDir "VANT-OpenSearch-Agent Tray.lnk"
if (Test-Path $shortcutPath) {
    Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
}

if (-not $KeepFiles -and (Test-Path $InstallDir)) {
    Remove-Item -Path $InstallDir -Recurse -Force
}

Write-Host "OpenSearch agent uninstalled."
Write-Host "Task removed: $TaskName"
if ($KeepFiles) {
    Write-Host "Files kept in: $InstallDir"
}
