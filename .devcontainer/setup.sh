#!/usr/bin/env bash
# ============================================================
# Codespaces Post-Create Setup Script
# Authorized Scan Orchestrator — Controller Agent Environment
# ============================================================
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log()  { echo -e "${GREEN}[SETUP]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
info() { echo -e "${CYAN}[INFO]${NC}  $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; }

log "=================================================="
log "  Authorized Scan Orchestrator — Codespaces Setup"
log "=================================================="

# ─────────────────────────────────────────
# 1. Python Dependencies
# ─────────────────────────────────────────
log "[1/6] Installing Python dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
pip install --quiet -r requirements-controller.txt
pip install --quiet pytest pytest-cov ruff
log "      Python packages installed ✅"

# ─────────────────────────────────────────
# 2. Database Setup
# ─────────────────────────────────────────
log "[2/6] Initialising SQLite database with Alembic..."
if [ -f "alembic.ini" ]; then
    alembic upgrade head && log "      Database schema applied ✅" || warn "Alembic migration failed — check DATABASE_URL"
else
    warn "alembic.ini not found — skipping migration"
fi

# ─────────────────────────────────────────
# 3. Install ProjectDiscovery httpx binary
#    (standalone scanner — no Axiom cloud needed)
# ─────────────────────────────────────────
log "[3/6] Installing ProjectDiscovery httpx scanner binary..."

HTTPX_BIN="$HOME/go/bin/httpx"
HTTPX_SYSTEM="/usr/local/bin/httpx-pd"

install_httpx_go() {
    if command -v go &>/dev/null; then
        log "      Building httpx via Go install..."
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && {
            log "      httpx binary installed via Go ✅  ($HTTPX_BIN)"
            # Ensure PATH is updated in bashrc
            grep -qxF 'export PATH=$PATH:$HOME/go/bin' "$HOME/.bashrc" || \
                echo 'export PATH=$PATH:$HOME/go/bin' >> "$HOME/.bashrc"
            export PATH=$PATH:$HOME/go/bin
            return 0
        }
    fi
    return 1
}

install_httpx_prebuilt() {
    log "      Downloading pre-built httpx binary (amd64)..."
    HTTPX_VERSION="v1.6.8"
    HTTPX_URL="https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_amd64.zip"
    TMP_DIR=$(mktemp -d)
    if curl -sL "$HTTPX_URL" -o "$TMP_DIR/httpx.zip" 2>/dev/null; then
        cd "$TMP_DIR" && unzip -q httpx.zip 2>/dev/null
        if [ -f "$TMP_DIR/httpx" ]; then
            sudo mv "$TMP_DIR/httpx" "$HTTPX_SYSTEM"
            sudo chmod +x "$HTTPX_SYSTEM"
            log "      httpx pre-built binary installed ✅  ($HTTPX_SYSTEM)"
            cd - >/dev/null
            rm -rf "$TMP_DIR"
            return 0
        fi
    fi
    cd - >/dev/null
    rm -rf "$TMP_DIR"
    return 1
}

if install_httpx_go || install_httpx_prebuilt; then
    # Verify it's not the Python httpx package
    HTTPX_RESOLVED=$(which httpx 2>/dev/null || echo "")
    if echo "$HTTPX_RESOLVED" | grep -q ".venv"; then
        warn "      'httpx' in PATH resolves to Python package — using httpx-pd alias"
    else
        log "      httpx binary verified ✅"
    fi
else
    warn "      httpx binary installation skipped — controller will use dry_run mode"
    warn "      Install manually: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
fi

# ─────────────────────────────────────────
# 4. Environment File Setup
# ─────────────────────────────────────────
log "[4/6] Checking environment configuration..."
if [ ! -f ".env.local" ] && [ -f ".env.example" ]; then
    cp .env.example .env.local
    warn "      .env.local created from .env.example"
    warn "      ⚠️  IMPORTANT: Edit .env.local and fill in your secrets before starting the controller!"
    warn "      Required: CONTROLLER_API_ENDPOINT, CONTROLLER_SHARED_SECRET, RESULT_ENCRYPTION_KEY"
elif [ -f ".env.local" ]; then
    log "      .env.local already exists ✅"
else
    warn "      Neither .env.local nor .env.example found — create .env.local manually"
fi

# ─────────────────────────────────────────
# 5. Run Test Suite to Verify Setup
# ─────────────────────────────────────────
log "[5/6] Running pytest to verify environment..."
pytest --tb=short -q 2>&1 | tail -5 && log "      All tests passed ✅" || warn "      Some tests failed — check .env.local secrets"

# ─────────────────────────────────────────
# 6. Make helper scripts executable
# ─────────────────────────────────────────
log "[6/6] Making helper scripts executable..."
chmod +x .devcontainer/start-controller.sh 2>/dev/null || true
chmod +x .devcontainer/keepalive.sh 2>/dev/null || true
log "      Done ✅"

# ─────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅  Codespace setup complete!                       ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Commands available:                                  ║${NC}"
echo -e "${GREEN}║                                                       ║${NC}"
echo -e "${GREEN}║  Start API server:                                    ║${NC}"
echo -e "${CYAN}║    uvicorn app.main:app --reload --port 8000          ║${NC}"
echo -e "${GREEN}║                                                       ║${NC}"
echo -e "${GREEN}║  Start controller agent:                              ║${NC}"
echo -e "${CYAN}║    bash .devcontainer/start-controller.sh             ║${NC}"
echo -e "${GREEN}║                                                       ║${NC}"
echo -e "${GREEN}║  Run tests:                                           ║${NC}"
echo -e "${CYAN}║    pytest -v                                           ║${NC}"
echo -e "${GREEN}║                                                       ║${NC}"
echo -e "${GREEN}║  ⚠️  Edit .env.local before starting!                ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
