param()

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path $Root ".venv"

Write-Host "[1/4] Creating virtual environment (if needed)..."
if (-not (Test-Path $Venv)) {
    python -m venv $Venv
}

$Python = Join-Path $Venv "Scripts\python.exe"

Write-Host "[2/4] Installing backend dependencies..."
& $Python -m pip install --upgrade pip | Out-Null
& $Python -m pip install -r (Join-Path $Root "backend\requirements.txt")

Write-Host "[3/4] Starting backend at http://127.0.0.1:8000 ..."
$backend = Start-Process -FilePath $Python -ArgumentList "-m uvicorn app:app --host 127.0.0.1 --port 8000 --app-dir `"$Root\backend`"" -PassThru

Write-Host "[4/4] Starting frontend at http://127.0.0.1:3000 ..."
$frontend = Start-Process -FilePath $Python -ArgumentList "-m http.server 3000 --directory `"$Root\frontend`"" -PassThru

Write-Host "Pipeline is running."
Write-Host "Frontend: http://127.0.0.1:3000"
Write-Host "Backend:  http://127.0.0.1:8000"
Write-Host "Real-time IDS: use UI 'Real-Time Engine' section or API /realtime/start"
Write-Host "Note: Live NIC mode may require admin and Npcap."
Write-Host "Press Enter to stop..."
[void][System.Console]::ReadLine()

Stop-Process -Id $backend.Id, $frontend.Id -Force -ErrorAction SilentlyContinue
