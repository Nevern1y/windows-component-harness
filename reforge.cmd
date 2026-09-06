@echo off
setlocal
set "REFORGE_LAUNCHER=%~dp0reforge-launch.ps1"
if not exist "%REFORGE_LAUNCHER%" (
  echo Reforge launcher not found: "%REFORGE_LAUNCHER%" 1>&2
  exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%REFORGE_LAUNCHER%" %*
exit /b %ERRORLEVEL%
