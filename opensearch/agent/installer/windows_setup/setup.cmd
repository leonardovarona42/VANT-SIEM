@echo off
setlocal

set "WORKDIR=%ProgramData%\VANT\OpenSearchAgentInstaller"
set "PACKAGE_ZIP=%WORKDIR%\package.zip"

if not exist "%WORKDIR%" mkdir "%WORKDIR%"
copy /Y "package.zip" "%PACKAGE_ZIP%" >nul

powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -Path '%PACKAGE_ZIP%' -DestinationPath '%WORKDIR%\package' -Force"
if errorlevel 1 (
  echo Failed to extract package.zip
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%WORKDIR%\package\Install-OpenSearchAgent.ps1' -RunNow"
if errorlevel 1 (
  echo Agent install failed.
  exit /b 1
)

echo Installation completed.
exit /b 0
