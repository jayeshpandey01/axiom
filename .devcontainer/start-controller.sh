#!/usr/bin/env bash
# ============================================================
# Controller Agent Launcher for GitHub Codespaces
# ============================================================
# Loads secrets from .env.local, validates config, then starts
# the polling daemon with auto-restart on crash.
# ============================================================
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[CTRL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC}  $1"; }

# ── 1. Load environment variables ─────────────────────────
ENV_FILE=".env.local"
if [ -f "$ENV_FILE" ]; then
    log "Loading environment from $ENV_FILE..."
    # Export all non-comment lines
    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a
else
    err ".env.local not found! Copy .env.example and fill in your values."
    err "  cp .env.example .env.local && nano .env.local"
    exit 1
fi

# ── 2. Validate required secrets ──────────────────────────
MISSING=""
[ -z "$CONTROLLER_API_ENDPOINT" ] && MISSING="$MISSING CONTROLLER_API_ENDPOINT"
[ -z "$CONTROLLER_SHARED_SECRET" ] && MISSING="$MISSING CONTROLLER_SHARED_SECRET"
[ -z "$RESULT_ENCRYPTION_KEY" ]    && MISSING="$MISSING RESULT_ENCRYPTION_KEY"

if [ -n "$MISSING" ]; then
    err "Missing required environment variables in .env.local:"
    for var in $MISSING; do
        err "  ❌  $var"
    done
    err "Edit .env.local and fill in the missing values, then re-run."
    exit 1
fi

log "Configuration validated ✅"
log "  API Endpoint: $CONTROLLER_API_ENDPOINT"
log "  Auth Mode:    ${AUTH_MODE:-api_key}"

# ── 3. Verify httpx binary is available ───────────────────
HTTPX_BIN=""
for candidate in "$HOME/go/bin/httpx" "/usr/local/bin/httpx-pd" "/usr/local/bin/httpx"; do
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
        # Exclude Python httpx from venv
        if ! echo "$candidate" | grep -q ".venv"; then
            HTTPX_BIN="$candidate"
            break
        fi
    fi
done

if [ -n "$HTTPX_BIN" ]; then
    HTTPX_VER=$("$HTTPX_BIN" -version 2>&1 | head -1 || echo "unknown")
    log "  Scanner:      $HTTPX_BIN ($HTTPX_VER)"
else
    warn "  Scanner:      httpx binary not found — controller will run in DRY-RUN mode"
    warn "  Install:      go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
fi

# ── 4. Add Go bin to PATH if needed ───────────────────────
if [ -d "$HOME/go/bin" ]; then
    export PATH=$PATH:$HOME/go/bin
fi

# ── 5. Start the controller with auto-restart loop ────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  🚀  Starting Controller Agent Daemon...         ║${NC}"
echo -e "${GREEN}║  Target: ${CYAN}${CONTROLLER_API_ENDPOINT}${GREEN}${NC}"
echo -e "${GREEN}║  Press Ctrl+C to stop                            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

RESTART_COUNT=0
MAX_RESTARTS=20      # Stop after 20 consecutive crashes to avoid spin-loop
BACKOFF=5            # Seconds between restarts

while true; do
    log "Starting python -m controller.agent (restart #$RESTART_COUNT)..."
    
    # Run the agent — it loops internally, so this only returns on crash/exit
    python -m controller.agent && {
        # Clean exit — normal shutdown
        log "Controller agent exited cleanly."
        break
    } || {
        EXIT_CODE=$?
        RESTART_COUNT=$((RESTART_COUNT + 1))
        
        if [ $RESTART_COUNT -ge $MAX_RESTARTS ]; then
            err "Controller crashed $MAX_RESTARTS times consecutively. Stopping to avoid loop."
            err "Check the logs above for the root cause."
            exit 1
        fi
        
        warn "Controller exited with code $EXIT_CODE. Restarting in ${BACKOFF}s... (crash #$RESTART_COUNT)"
        sleep $BACKOFF
        
        # Exponential backoff capped at 60s
        BACKOFF=$((BACKOFF < 60 ? BACKOFF * 2 : 60))
    }
done
