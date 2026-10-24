@echo off
cd /d "c:\Users\harsh\OneDrive\Desktop\anti gravity  soc"
title AEGIS-SOC // Accuracy Benchmark
cls
echo ====================================================================
echo       AEGIS-SOC // 3-MODE ABLATION ACCURACY BENCHMARK
echo ====================================================================
echo.
echo [*] Running 50-sample accuracy evaluation...
echo [*] Testing Mode 1 (Baseline), Mode 2 (ML), Mode 3 (AEGIS-SOC Full)
echo.
"C:\Users\harsh\AppData\Local\Programs\Python\Python311\python.exe" tools/evaluate_accuracy.py 50
echo.
echo [+] Benchmark complete!
echo.
pause
