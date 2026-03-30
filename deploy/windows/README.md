# Offline Deployment Package — Windows Server

## Overview

- Backend: Python Flask API (`backend/app.py`) with SQLite by default; PostgreSQL optional.
- Frontend: React app built to static assets (`frontend/build`).
- Package includes pre-downloaded Windows wheels for offline `pip` install and static frontend build.

## Prerequisites (Windows Server)

- Windows Server 2019/2022 x64
- Python 3.10 x64 installed and on PATH (e.g., `C:\Python310\python.exe`)
- IIS installed (Web Server role) for serving static frontend

## Prepare Offline Bundle (Connected Machine)

1. Build frontend static assets
   - `cd frontend`
   - `npm ci`
   - `npm run build`

2. Download Windows wheels for backend dependencies
   - `cd ..`
   - `python -m pip install --upgrade pip`
   - `mkdir -p deploy/windows/wheels`
   - `python -m pip download --platform win_amd64 --python-version 3.10 --only-binary=:all: -r requirements.txt -d deploy/windows/wheels`

3. Create bundle directory
   - Include:
     - `backend/` (source code)
     - `frontend/build/` (static assets)
     - `deploy/windows/wheels/` (downloaded wheels)
     - `requirements.txt` (root)
     - `.env.example` from `backend/` (copy and edit later on server)

4. Archive
   - Zip the above into `FRR-offline-windows.zip`

## Install on Windows Server (Offline)

1. Unpack bundle
   - `C:\FRR\backend`
   - `C:\FRR\frontend\build`
   - `C:\FRR\deploy\windows\wheels`

2. Backend Python environment
   - `cd C:\FRR\backend`
   - `C:\Python310\python.exe -m venv venv`
   - `C:\FRR\backend\venv\Scripts\pip.exe install --no-index --find-links C:\FRR\deploy\windows\wheels -r C:\FRR\requirements.txt`

3. Backend configuration
   - Create `C:\FRR\backend\.env` with:
     - `DATABASE_URL=sqlite:///C:\FRR\backend\firewall_review.db`
     - `SECRET_KEY=<set-a-secret>`
     - `FLASK_ENV=production`
     - `FLASK_DEBUG=False`

4. Run backend
   - `cd C:\FRR\backend`
   - `C:\FRR\backend\venv\Scripts\python.exe app.py`
   - API listens on `http://0.0.0.0:5001/`

5. Configure IIS for frontend
   - Create new website pointing to `C:\FRR\frontend\build`
   - Bind to desired port (e.g., 8080 or 80)
   - Add URL Rewrite rules (if using API under different host/port):
     - Allow `/api/*` to proxy to `http://127.0.0.1:5001/*`
   - Alternatively, set `REACT_APP_API_URL` at build time to `http://server:5001` and avoid proxying.

## Verification

- Health: `GET http://127.0.0.1:5001/health`
- Upload sample rules, run review, check results
- Export endpoints:
  - Excel: `GET /api/export/excel/<session_id>?include_compliant=false`
  - CSV: `GET /api/export/csv/<session_id>?include_compliant=false`
  - PDF: `GET /api/export/pdf/<session_id>?include_compliant=false`

## Notes

- Backend reads `DATABASE_URL` from `.env`; falls back to local SQLite file.
- `requirements.txt` includes `openpyxl` and `reportlab` for exports.
- Deny/block/drop are treated as compliant; permit/allow rules can be flagged.

## Optional — Windows Service

- Use Task Scheduler to run `C:\FRR\backend\venv\Scripts\python.exe C:\FRR\backend\app.py` at startup.
- Or use NSSM to install the Python script as a service.

