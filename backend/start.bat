@echo off
echo ============================
echo  Log Sentinel - Backend
echo ============================

: Set your Groq API key here (get one free at https://console.groq.com)
set GROQ_API_KEY=your_groq_api_key_here

:: Install dependencies if needed
pip install -r requirements.txt

:: Start the server
echo Starting API server on http://localhost:8000
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
