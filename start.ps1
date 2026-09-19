# Quick start for Windows PowerShell.
# Generates the synthetic dataset (if missing) and launches the API server,
# which also serves the built frontend at http://127.0.0.1:8000

$ErrorActionPreference = "Stop"
Set-Location "$PSScriptRoot\backend"

if (-not (Test-Path "data\synthetic\auth_gateway.csv")) {
    Write-Host "Generating synthetic dataset..." -ForegroundColor Cyan
    python -m data.generate
}

# Build frontend if a dist is not present yet
if (-not (Test-Path "$PSScriptRoot\frontend\dist\index.html")) {
    Write-Host "Building frontend..." -ForegroundColor Cyan
    Push-Location "$PSScriptRoot\frontend"
    if (-not (Test-Path "node_modules")) { npm install }
    npm run build
    Pop-Location
}

Write-Host "Starting server on http://127.0.0.1:8000 ..." -ForegroundColor Green
python -m uvicorn app.main:app --port 8000
