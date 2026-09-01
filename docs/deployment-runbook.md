# Production Deployment & Operations Runbook

This document provides complete instructions for deploying the **Authorized Scan Orchestrator** to Render (API & Worker) and connecting the isolated **Linux Controller VPS**.

---

## 1. Architecture Overview

* **Render Platform**: Hosts the FastAPI Web Service, Background Maintenance Worker, PostgreSQL Database, and Redis/Key Value.
* **Linux Controller VPS**: Runs on a separate cloud VPS (or WSL2 for dev), holding cloud provider credentials and managing disposable Axiom scanner VMs.
* **Object Storage (S3 / R2)**: Stores client-side encrypted raw tool outputs with 30-day retention policies.

---

## 2. Environment Variables Checklist

### Render Web Service & Worker (`render.yaml`)

| Variable | Description | Production Value Example |
| :--- | :--- | :--- |
| `APP_ENV` | Application environment | `production` |
| `AUTH_MODE` | Authentication mechanism | `oidc` |
| `OIDC_ISSUER` | OpenID Connect Issuer URL | `https://auth.yourcompany.com/` |
| `OIDC_AUDIENCE` | Target API Audience | `https://api.scantool.yourcompany.com` |
| `OIDC_JWKS_URL` | Public JWKS endpoint | `https://auth.yourcompany.com/.well-known/jwks.json` |
| `DATABASE_URL` | Render PostgreSQL Connection URI | Auto-populated by Render Blueprint |
| `RATE_LIMIT_REDIS_URL` | Render Key Value URI | Auto-populated by Render Blueprint |
| `CONTROLLER_SHARED_SECRET` | 64-char random hex secret for HMAC | High-entropy random secret |
| `RESULT_STORAGE_BUCKET` | AWS S3 or Cloudflare R2 bucket name | `scantool-raw-artifacts` |
| `RESULT_ENCRYPTION_KEY` | Fernet 32-byte URL-safe base64 key | Generated via `Fernet.generate_key()` |
| `RESULT_RETENTION_DAYS` | Data retention policy (days) | `30` |

### Controller VPS (`.env` on Linux VPS)

| Variable | Description | Production Value Example |
| :--- | :--- | :--- |
| `CONTROLLER_API_ENDPOINT` | Public Render Web Service URL | `https://scan-tool-api.onrender.com` |
| `CONTROLLER_SHARED_SECRET` | Matches Render `CONTROLLER_SHARED_SECRET` | High-entropy random secret |
| `CONTROLLER_MAX_FLEET_SIZE` | Maximum simultaneous VMs | `2` (Staging) / `10` (Production) |
| `CONTROLLER_SCAN_TIMEOUT_SECONDS` | Max scan runtime before auto-kill | `900` (15 minutes) |
| `CONTROLLER_DROPLET_TTL_MINUTES` | Watchdog max droplet age | `30` |

---

## 3. Deployment Steps

### Step 1: Deploy API Platform to Render
1. Push repository to your private GitHub organization.
2. In Render Dashboard, click **New +** $\to$ **Blueprint**.
3. Select your repository. Render will automatically parse [render.yaml](file:///c:/Users/jayes/Downloads/Scan_tool/render.yaml) and create:
   - `scan-tool-api` (Web Service)
   - `scan-tool-worker` (Background Maintenance Worker)
   - `scan-tool-db` (Managed Postgres)
   - `scan-tool-rate-limit` (Managed Key Value / Redis)
4. Fill in the non-synced environment secrets (`OIDC_*`, `RESULT_STORAGE_*`, `RESULT_ENCRYPTION_KEY`).
5. Run migrations via Render Shell / SSH:
   ```bash
   alembic upgrade head
   ```

### Step 2: Provision & Deploy the Linux Controller VPS
1. Follow the [Linux Controller Setup Guide](file:///c:/Users/jayes/Downloads/Scan_tool/docs/controller-setup-guide.md) on a fresh Ubuntu VPS.
2. Set up Axiom with your Cloud Provider API token:
   ```bash
   $HOME/.axiom/interact/axiom-configure
   $HOME/.axiom/interact/axiom-build
   ```
3. Clone this repository on the VPS:
   ```bash
   git clone https://github.com/your-org/Scan_tool.git /opt/scan_tool
   cd /opt/scan_tool
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements-controller.txt
   ```
4. Create `/opt/scan_tool/.env` with `CONTROLLER_API_ENDPOINT` and `CONTROLLER_SHARED_SECRET`.
5. Install systemd service for continuous polling:
   ```ini
   # /etc/systemd/system/scan-controller.service
   [Unit]
   Description=Scan Tool Axiom Controller Daemon
   After=network.target

   [Service]
   Type=simple
   User=ubuntu
   WorkingDirectory=/opt/scan_tool
   EnvironmentFile=/opt/scan_tool/.env
   ExecStart=/opt/scan_tool/.venv/bin/python -m controller.agent
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```
6. Start the daemon:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now scan-controller
   ```

---

## 4. Emergency Procedures

### 1. Emergency Scan Cancellation
To immediately stop a running scan and terminate all cloud VMs:
```bash
curl -X POST "https://scan-tool-api.onrender.com/v1/scans/{scan_id}/cancel" \
     -H "Authorization: Bearer <OPERATOR_JWT>"
```

### 2. Manual Orphan Teardown (Emergency Cloud Purge)
If the controller daemon is killed or network connectivity is lost during an active scan:
```bash
# SSH into Controller VPS and run the emergency reaper:
python3 -m controller.watchdog
```
Or use the raw Axiom command:
```bash
$HOME/.axiom/interact/axiom-rm "*" -f
```
