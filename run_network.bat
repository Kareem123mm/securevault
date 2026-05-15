@echo off
title SecureVault Network Launcher
cd /d "%~dp0"

echo.
echo  ============================================================
echo    SECUREVAULT NETWORK LAUNCHER
echo  ============================================================
echo.
echo  Starting Socket Server    ^>  new window
echo  Starting Monitor          ^>  new window
echo  Starting Interactive CLI  ^>  this window
echo.
timeout /t 1 /nobreak >nul

:: Launch the socket server in its own window
start "SecureVault - Socket Server" cmd /k "python network\socket_server.py"

:: Give the server 2 seconds to bind the port before the monitor checks it
timeout /t 2 /nobreak >nul

:: Launch the real-time monitor in its own window
start "SecureVault - Monitor" cmd /k "python network\monitor.py"

:: Small pause so the server has written its first status file
timeout /t 1 /nobreak >nul

:: Run the interactive client in this window
python network\interactive_client.py
