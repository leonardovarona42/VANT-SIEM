param(
    [switch]$Stop,
    [switch]$Restart
)

$VENV = "C:\Users\SysAdmin\Documents\develop\venv-schrodinger"
$PROJECT_DIR = "C:\Users\SysAdmin\Documents\develop\VANT-SIEM"
$NGINX_DIR = "C:\nginx"
$LOG_DIR = "$PROJECT_DIR\logs"
$PID_FILE = "$LOG_DIR\vantsiem.pid"

if (-not (Test-Path $LOG_DIR)) { New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null }

function Start-Nginx {
    Write-Host "Starting nginx..." -ForegroundColor Cyan
    $nginx = Start-Process -FilePath "$NGINX_DIR\nginx.exe" -WorkingDirectory $NGINX_DIR -NoNewWindow -PassThru
    Start-Sleep -Seconds 1
    Write-Host "nginx PID: $($nginx.Id)" -ForegroundColor Green
}

function Stop-Nginx {
    Write-Host "Stopping nginx..." -ForegroundColor Yellow
    & "$NGINX_DIR\nginx.exe" -s stop 2>$null
    Start-Sleep -Seconds 1
}

function Start-Vantsiem {
    Write-Host "Starting VANT-SIEM (waitress)..." -ForegroundColor Cyan
    $log = "$LOG_DIR\vantsiem.log"
    $process = Start-Process -FilePath "$VENV\Scripts\python.exe" `
        -ArgumentList "$PROJECT_DIR\serve_vantsiem.py" `
        -WorkingDirectory $PROJECT_DIR `
        -NoNewWindow -PassThru -RedirectStandardOutput $log -RedirectStandardError $log
    $process.Id | Out-File -FilePath $PID_FILE -Force
    Write-Host "VANT-SIEM PID: $($process.Id)" -ForegroundColor Green
}

function Stop-Vantsiem {
    if (Test-Path $PID_FILE) {
        $pid = Get-Content $PID_FILE
        Write-Host "Stopping VANT-SIEM (PID: $pid)..." -ForegroundColor Yellow
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        Remove-Item $PID_FILE -Force -ErrorAction SilentlyContinue
    }
}

if ($Stop) {
    Stop-Vantsiem
    Stop-Nginx
    Write-Host "Stopped." -ForegroundColor Green
    exit
}

if ($Restart) {
    Stop-Vantsiem
    Stop-Nginx
    Start-Sleep -Seconds 2
}

Write-Host "=== VANT-SIEM Windows Deployment ===" -ForegroundColor Magenta
Write-Host "Project: $PROJECT_DIR" -ForegroundColor Gray
Write-Host "Venv: $VENV" -ForegroundColor Gray

Stop-Nginx
Stop-Vantsiem
Start-Sleep -Seconds 1

Start-Vantsiem
Start-Sleep -Seconds 3
Start-Nginx

Write-Host ""
Write-Host "=== VANT-SIEM is running ===" -ForegroundColor Green
Write-Host "Web: http://localhost" -ForegroundColor White
Write-Host "Logs: $LOG_DIR\vantsiem.log" -ForegroundColor Gray
