@echo off
cd /d "c:\Users\harsh\OneDrive\Desktop\anti gravity  soc"
title AEGIS-SOC // Package Installer
cls
echo ====================================================================
echo       AEGIS-SOC // PACKAGE INSTALLER
echo ====================================================================
echo.
echo [*] Installing all required Python packages...
echo [*] This may take 1-3 minutes. Please wait.
echo.
"C:\Users\harsh\AppData\Local\Programs\Python\Python311\python.exe" -m pip install -r requirements.txt
echo.
echo [+] Installation complete!
echo [*] You can now run START_SERVER.bat to launch the platform.
echo.
pause
