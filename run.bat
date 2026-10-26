@echo off
title CyberShield - SOC Incident Reporting System
echo ====================================================================
echo  CYBERSHIELD: Cybersecurity Incident Reporting & SOC Triage System
echo ====================================================================
echo.
echo Starting application on http://127.0.0.1:5000 ...
echo Press Ctrl+C in this window to stop the server.
echo.
python app.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Trying direct python path...
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" app.py
)
pause
