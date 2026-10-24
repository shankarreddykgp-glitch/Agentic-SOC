@echo off
cd /d "c:\Users\harsh\OneDrive\Desktop\anti gravity  soc"
title AEGIS-SOC // Autonomous Cyber Defense Platform
cls
echo ====================================================================
echo       AEGIS-SOC // TACTICAL CYBER DEFENSE SERVER LAUNCHER
echo ====================================================================
echo.
echo [*] Starting FastAPI server on http://localhost:8000
echo [*] Multi-Agent Swarm (LangGraph) + ChromaDB RAG Vector Store
echo.
echo [*] Open your browser and go to: http://localhost:8000
echo [*] Press CTRL+C to stop the server
echo.
"C:\Users\harsh\AppData\Local\Programs\Python\Python311\python.exe" server.py
pause
