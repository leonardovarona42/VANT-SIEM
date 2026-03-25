param(
    [string]$PythonExe = "C:\Users\leonardo.varona\3D Objects\develop\venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"

powershell -ExecutionPolicy Bypass -File ".\opensearch_agents\windows\build_setup.ps1" -PythonExe $PythonExe
