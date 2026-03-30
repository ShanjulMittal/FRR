# Offline Deployment Guide

## Overview
This document describes packaging and deploying the Firewall Rule Review (FRR) application in an offline environment using Docker. It includes all supporting libraries, application configuration, container images, and steps to verify the deployment.

## Components
- Backend API: Flask + SQLAlchemy, served by `gunicorn` on port `5001`
- Frontend UI: React, built and served by Nginx on port `8080`
- Database: SQLite file persisted inside the backend container volume

## Prerequisites
- Docker Engine 24+
- Docker Compose V2
- A connected machine to build images and export them for offline use

## Build (Connected Machine)
1. Set environment (optional)
   - Backend DB path via `DATABASE_URL` (defaults to `sqlite:////data/firewall_review.db`)
   - Frontend API URL build arg `REACT_APP_API_URL` (defaults to `http://localhost:5001`)
2. Build and package images
   ```bash
   docker compose build
   docker save -o frr-backend.tar frr-backend
   docker save -o frr-frontend.tar frr-frontend
   ```
3. Copy tar files to the offline target

## Deploy (Offline Target)
1. Load images
   ```bash
   docker load -i frr-backend.tar
   docker load -i frr-frontend.tar
   ```
2. Start services
   ```bash
   docker compose up -d
   ```
3. Verify
   - Backend health: `curl http://localhost:5001/health`
   - Frontend: `http://localhost:8080/`

## Configuration
- Backend
  - `DATABASE_URL`: Example `sqlite:////data/firewall_review.db` (default)
  - Timezone: `TZ=Asia/Kolkata`
  - Port: `5001` exposed in compose
- Frontend
  - Build arg `REACT_APP_API_URL` used during build to set API base URL
  - Nginx proxies `/api/*` to `backend:5001`

## Data Persistence
- SQLite file is stored under the backend container volume `frr-backend-data`
- To backup/restore, use volume commands or mount a host directory in `docker-compose.yml`

## Common Operations
- View logs
  ```bash
  docker compose logs -f backend
  docker compose logs -f frontend
  ```
- Restart services
  ```bash
  docker compose restart
  ```
- Stop services
  ```bash
  docker compose down
  ```

## Security Notes
- Do not store secrets in the repository. Use environment variables or Docker secrets where needed.
- SQLite is suitable for single-user/offline scenarios. For multi-user or larger deployments, use Postgres and set `DATABASE_URL=postgresql+psycopg2://user:pass@db-host:5432/dbname`.

## Troubleshooting
- Frontend cannot reach API: ensure `REACT_APP_API_URL` points to `http://localhost:5001` at build time, or rely on Nginx proxy (`/api/*`).
- Backend DB locked errors: avoid concurrent writes; SQLite is file-based.
- Timezone handling: container sets `TZ=Asia/Kolkata`; adjust as needed.

## Appendix: Building Without Compose
```bash
# Backend
docker build -t frr-backend ./backend
docker run -d --name frr-backend -p 5001:5001 -e DATABASE_URL=sqlite:////data/firewall_review.db -v frr-backend-data:/data frr-backend

# Frontend
docker build -t frr-frontend --build-arg REACT_APP_API_URL=http://localhost:5001 ./frontend
docker run -d --name frr-frontend -p 8080:80 --link frr-backend frr-frontend
```
