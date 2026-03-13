param(
    [string]$TaskName = "VANT-OpenSearch-Service",
    [string]$PythonExe = "C:\Users\leonardo.varona\3D Objects\develop\venv\Scripts\python.exe",
    [string]$WorkDir = "C:\Users\leonardo.varona\3D Objects\develop\VANT-SIEM",
    [string]$DbHost = "localhost",
    [string]$DbPort = "5432",
    [string]$DbName = "opensearch",
    [string]$DbUser = "postgres",
    [string]$DbPassword = "postgres",
    [string]$ServiceHost = "0.0.0.0",
    [string]$ServicePort = "9201"
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    throw "Run PowerShell as Administrator."
}

if (-not (Test-Path $PythonExe)) {
    throw "Python not found: $PythonExe"
}
if (-not (Test-Path (Join-Path $WorkDir "opensearch_service\service\app.py"))) {
    throw "Service app not found under: $WorkDir"
}

$logDir = Join-Path $WorkDir "dist\opensearch-service-logs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$stdoutLog = Join-Path $logDir "service.out.log"
$stderrLog = Join-Path $logDir "service.err.log"

$cmd = @(
    '$env:OS_SERVICE_HOST=''' + $ServiceHost + ''';'
    '$env:OS_SERVICE_PORT=''' + $ServicePort + ''';'
    '$env:OS_DB_HOST=''' + $DbHost + ''';'
    '$env:OS_DB_PORT=''' + $DbPort + ''';'
    '$env:OS_DB_NAME=''' + $DbName + ''';'
    '$env:OS_DB_USER=''' + $DbUser + ''';'
    '$env:OS_DB_PASSWORD=''' + $DbPassword + ''';'
    '$env:OS_AUTH_MODE=''none'';'
    '& ''' + $PythonExe + ''' ''' + (Join-Path $WorkDir "opensearch_service\service\app.py") + ''' 1>>''' + $stdoutLog + ''' 2>>''' + $stderrLog + ''''
) -join " "

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command $cmd"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "Installed task: $TaskName"
Write-Host "Logs: $logDir"
