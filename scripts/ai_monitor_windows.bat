@echo off
REM Script para ejecutar monitoreo automático de alertas con IA en Windows
REM Configurar en Task Scheduler para que se ejecute cada 5 minutos

REM Configuración - AJUSTAR SEGÚN TU ENTORNO
set PROJECT_PATH=C:\Users\leonardo.varona\3D Objects\develop\CORE
set VENV_PATH=%PROJECT_PATH%\venv
set PYTHON_EXE=%VENV_PATH%\Scripts\python.exe
set MANAGE_PY=%PROJECT_PATH%\manage.py
set LOG_FILE=%PROJECT_PATH%\logs\ai_monitor.log

REM Timestamp para logs
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set TIMESTAMP=%datetime:~0,4%-%datetime:~4,2%-%datetime:~6,2% %datetime:~8,2%:%datetime:~10,2%:%datetime:~12,2%

echo [%TIMESTAMP%] Iniciando monitoreo automático de alertas... >> "%LOG_FILE%"

REM Cambiar al directorio del proyecto
cd /d "%PROJECT_PATH%"
if errorlevel 1 (
    echo [%TIMESTAMP%] ERROR: No se pudo cambiar al directorio %PROJECT_PATH% >> "%LOG_FILE%"
    exit /b 1
)

REM Verificar que Python existe
if not exist "%PYTHON_EXE%" (
    echo [%TIMESTAMP%] ERROR: Python no encontrado en %PYTHON_EXE% >> "%LOG_FILE%"
    exit /b 1
)

REM Ejecutar el comando de monitoreo
"%PYTHON_EXE%" "%MANAGE_PY%" ai_alert_monitor >> "%LOG_FILE%" 2>&1

REM Verificar código de salida
if %errorlevel% equ 0 (
    echo [%TIMESTAMP%] Monitoreo completado exitosamente >> "%LOG_FILE%"
) else (
    echo [%TIMESTAMP%] ERROR: Monitoreo falló con código %errorlevel% >> "%LOG_FILE%"
)

echo [%TIMESTAMP%] Fin del monitoreo automático >> "%LOG_FILE%"
echo. >> "%LOG_FILE%"

exit /b %errorlevel%