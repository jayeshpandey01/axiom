#!/usr/bin/env bash
# ============================================================
# Codespaces Session Keepalive Script
# ============================================================
# GitHub Codespaces idles and stops after 30 minutes of no
# activity. This script prevents that by generating periodic
# terminal output while the controller agent runs in a
# separate terminal tab/pane.
#
# USAGE: Run in a separate terminal while the controller runs:
#   bash .devcontainer/keepalive.sh
#
# Or combine both in one tmux session:
#   tmux new-session \; \
#     send-keys 'bash .devcontainer/start-controller.sh' Enter \; \
#     split-window -h \; \
#     send-keys 'bash .devcontainer/keepalive.sh' Enter
# ============================================================

INTERVAL=${1:-900}   # Default: ping every 15 minutes (900s)
                     # Max idle timeout in Codespaces = 4 hours
                     # So 15 min intervals are very conservative

GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}[KEEPALIVE]${NC} Session keepalive started."
echo -e "${GREEN}[KEEPALIVE]${NC} Pinging every ${INTERVAL}s to prevent idle timeout."
echo -e "${GREEN}[KEEPALIVE]${NC} Press Ctrl+C to stop."
echo ""

COUNT=0
START_TIME=$(date +%s)

while true; do
    sleep "$INTERVAL"
    COUNT=$((COUNT + 1))
    ELAPSED=$(( $(date +%s) - START_TIME ))
    HOURS=$((ELAPSED / 3600))
    MINUTES=$(( (ELAPSED % 3600) / 60 ))
    
    echo -e "${CYAN}[KEEPALIVE]${NC} ♥  Alive — $(date '+%Y-%m-%d %H:%M:%S') | Session uptime: ${HOURS}h ${MINUTES}m | Ping #${COUNT}"
    
    # Also do a quick health check against the API if endpoint is set
    if [ -n "$CONTROLLER_API_ENDPOINT" ]; then
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${CONTROLLER_API_ENDPOINT}/health" 2>/dev/null || echo "ERR")
        if [ "$STATUS" = "200" ]; then
            echo -e "${GREEN}[KEEPALIVE]${NC} API health: ✅ 200 OK"
        else
            echo -e "${GREEN}[KEEPALIVE]${NC} API health: HTTP $STATUS"
        fi
    fi
done
