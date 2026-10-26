@echo off
title CyberShield - Test Suite
echo Running CyberShield Automated Verification Tests...
echo.
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" test_app.py
pause
