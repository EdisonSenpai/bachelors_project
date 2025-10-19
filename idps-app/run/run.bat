@echo off
cd /d %~dp0
:: chcp 65001 >nul
title IDPS Launcher
cls

:ASCII
:: Afiseaza ASCII Art
type ascii-art.txt

:MENU
echo.
echo ===================== IDPS LAUNCHER ===========================
echo 1. Start IDPS App
echo 2. Stop Servers (Select)
echo 3. Exit
echo ===============================================================
echo.

set /p choice=Select an option [1-3]:

if "%choice%"=="1" (
    echo.
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
    echo > Virtual environment activated.
    echo > Starting servers...
    start cmd /k python backend\app.py
    start cmd /k python backend\ai_api.py
    start cmd /k python backend\suricata_api.py
    echo > All servers launched in separate windows.
    goto MENU
)

:: echo Activare mediu virtual...
:: call .venv\Scripts\activate.bat

:: echo Pornire app.py...
:: start cmd /k python backend\app.py

:: echo Pornire ai_api.py...
:: start cmd /k python backend\ai_api.py

:: echo Pornire suricata_api.py...
:: start cmd /k python backend\suricata_api.py

:: echo Toate serviciile au fost lansate in ferestre separate.

if "%choice%"=="2" goto STOPMENU

if "%choice%"=="3" (
    echo > Exiting...
    timeout /t 1 >nul
    exit
)

echo > Invalid option. Please try again.
echo.
goto MENU


:STOPMENU
cls
echo.
echo ================ STOP SERVER MENU ==================
echo a. Stop ALL Python processes
echo b. Stop ONLY app.py
echo c. Stop ONLY ai_api.py
echo d. Stop ONLY suricata_api.py
echo e. Back to Main Menu
echo ====================================================
echo.

set /p stopChoice=Select option [a-e]: 

if "%stopChoice%"=="a" (
    echo Stopping all python processes...
    taskkill /F /IM python.exe >nul 2>&1
    taskkill /F /IM python3.exe >nul 2>&1
    echo > All Python processes terminated.
    goto MENU
)

if "%stopChoice%"=="b" (
    echo Stopping app.py...
    for /f "tokens=2 delims=," %%a in ('tasklist /v /fo csv ^| findstr /i "app.py"') do taskkill /PID %%a /F >nul 2>&1
    echo > app.py stopped, if it was running.
    goto MENU
)

if "%stopChoice%"=="c" (
    echo Stopping ai_api.py...
    for /f "tokens=2 delims=," %%a in ('tasklist /v /fo csv ^| findstr /i "ai_api.py"') do taskkill /PID %%a /F >nul 2>&1
    echo > ai_api.py stopped, if it was running.
    goto MENU
)

if "%stopChoice%"=="d" (
    echo Stopping suricata_api.py...
    for /f "tokens=2 delims=," %%a in ('tasklist /v /fo csv ^| findstr /i "suricata_api.py"') do taskkill /PID %%a /F >nul 2>&1
    echo > suricata_api.py stopped, if it was running.
    goto MENU
)

if "%stopChoice%"=="e" goto ASCII

echo > Invalid option. Try again.
echo.
goto STOPMENU