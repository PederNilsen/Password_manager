@echo off
setlocal
echo =============================================
echo   Password Manager Demo Setup
echo =============================================
echo.

:: ===========================
:: Step 1: Try to find MySQL
:: ===========================
set FOUND_MYSQL=

set MYSQL_PATHS="C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" "C:\Program Files (x86)\MySQL\MySQL Server 8.0\bin\mysql.exe" "C:\xampp\mysql\bin\mysql.exe" "C:\wamp64\bin\mysql\mysql8.0.28\bin\mysql.exe"

for %%p in (%MYSQL_PATHS%) do (
    if exist %%p (
        set "FOUND_MYSQL=%%~p"
        goto mysqlfound
    )
)

echo MySQL executable not found in common locations.
set /p FOUND_MYSQL="Please enter full path to mysql.exe (e.g., C:\xampp\mysql\bin\mysql.exe): "
if defined FOUND_MYSQL set "FOUND_MYSQL=%FOUND_MYSQL:"=%"

:mysqlfound
if not exist "%FOUND_MYSQL%" (
    echo MySQL executable not found. Setup cannot continue.
    pause
    exit /b 1
)

:: ===========================
:: Step 2: Ask for DB credentials
:: ===========================
set /p DB_USER="Enter MySQL username (default: root): "
if "%DB_USER%"=="" set DB_USER=root

:: Read password via PowerShell SecureString so it is NOT echoed and NOT
:: stored in command history. The plaintext stays in the local variable
:: only long enough to set MYSQL_PWD; we clear MYSQL_PWD afterwards.
set "DB_PASS="
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "$p = Read-Host -AsSecureString 'Enter MySQL password'; [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p))"`) do set "DB_PASS=%%i"

:: ===========================
:: Step 3: Run SQL setup using MYSQL_PWD env var (NOT -p on the cmdline)
:: ===========================
echo Running database setup...
set "MYSQL_PWD=%DB_PASS%"
"%FOUND_MYSQL%" -u "%DB_USER%" < "%~dp0setup.sql"
set RC=%ERRORLEVEL%
set MYSQL_PWD=
set DB_PASS=

if not "%RC%"=="0" (
    echo There was an error setting up the database.
    pause
    exit /b %RC%
)

echo.
echo Database setup complete.
echo.
echo Next steps:
echo   1. Copy src\main\resources\Password.properties.example to Password.properties
echo   2. Fill in your MySQL host/user/port and pwd
echo   3. Leave blind_index_key blank on first run; the app will print one to paste back
echo.
echo Do NOT commit Password.properties to git (it is already in .gitignore).
pause
endlocal
