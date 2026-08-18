@echo off
echo Setting up Secure Persona Prediction System...
echo.

REM Create virtual environment
python -m venv venv
call venv\Scripts\activate

REM Upgrade pip
python -m pip install --upgrade pip

REM Install requirements
pip install -r requirements.txt

REM Create necessary directories
mkdir data 2>nul
mkdir data\encrypted_files 2>nul
mkdir data\audit_logs 2>nul
mkdir app 2>nul
mkdir app\dashboard 2>nul
mkdir app\security 2>nul
mkdir app\services 2>nul
mkdir app\database 2>nul
mkdir config 2>nul
mkdir .streamlit 2>nul

REM Setup database
python setup_database.py

REM Start Redis (if available)
echo Starting services...
start /B redis-server 2>nul || echo Redis not installed, using fallback

echo.
echo ✅ Setup complete!
echo.
echo To start the application:
echo 1. Activate virtual environment: venv\Scripts\activate
echo 2. Run: streamlit run streamlit_app.py
echo.
pause