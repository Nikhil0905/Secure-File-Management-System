@echo off
echo Setting up Secure File Management System...
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed! Please install Python 3.8 or higher.
    pause
    exit /b 1
)

:: Create virtual environment if it doesn't exist
if not exist .venv (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Failed to create virtual environment!
        pause
        exit /b 1
    )
)

:: Activate virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo Failed to activate virtual environment!
    pause
    exit /b 1
)

:: Upgrade pip to latest version
echo Upgrading pip to latest version...
python -m pip install --upgrade pip
if errorlevel 1 (
    echo Failed to upgrade pip!
    pause
    exit /b 1
)

:: Install requirements
echo Installing required packages...
pip install -r requirements.txt
if errorlevel 1 (
    echo Failed to install requirements!
    pause
    exit /b 1
)

:: Create storage directory if it doesn't exist
if not exist secure_storage (
    echo Creating storage directory...
    mkdir secure_storage
)

:: Verify environment variables
echo Verifying environment variables...
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print('MAX_FILE_SIZE:', os.getenv('MAX_FILE_SIZE'))" > nul 2>&1
if errorlevel 1 (
    echo Warning: Environment variables may not be properly set!
    echo Please check your .env file.
)

echo.
echo Setup completed successfully!
echo.
echo To start using the system:
echo 1. Register a new user: python main.py register your_username
echo 2. Login: python main.py login your_username
echo 3. Upload files: python main.py upload "path\to\your\file"
echo 4. List files: python main.py list
echo 5. Download files: python main.py download filename "path\to\save"
echo 6. Share files: python main.py share filename username
echo 7. Delete files: python main.py delete filename
echo 8. Logout: python main.py logout
echo.
pause 