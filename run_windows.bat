@echo off
setlocal
cd /d "%~dp0"
python -m pip install -r requirements.txt
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000
