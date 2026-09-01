# Codespaces Secrets Configuration
# 
# GitHub Codespaces will automatically inject secrets you configure
# in GitHub Settings → Secrets and Variables → Codespaces
#
# Add the following secrets in GitHub UI:
# 1. Go to: https://github.com/settings/codespaces
# 2. Click "New secret"
# 3. Add each variable below
#
# ─────────────────────────────────────────────────────────
# REQUIRED SECRETS (must be set for controller to work):
# ─────────────────────────────────────────────────────────
#
# CONTROLLER_API_ENDPOINT
#   Your deployed Render.com API URL
#   Example: https://axiom-xjkc.onrender.com
#
# CONTROLLER_SHARED_SECRET
#   Must match CONTROLLER_SHARED_SECRET on your Render deployment
#   Generate: python -c "import secrets; print(secrets.token_urlsafe(48))"
#
# RESULT_ENCRYPTION_KEY
#   Must match RESULT_ENCRYPTION_KEY on your Render deployment
#   Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
#
# ─────────────────────────────────────────────────────────
# OPTIONAL SECRETS:
# ─────────────────────────────────────────────────────────
#
# API_KEY
#   Operator API key for running the live E2E test script
#
# ADMIN_API_KEY
#   Admin API key for registering targets in the live E2E test
#
# DATABASE_URL
#   Leave unset to use SQLite (default for Codespaces dev)
#   Set to postgres:// only if you want to use a remote DB
#
# ─────────────────────────────────────────────────────────
# LOCAL OVERRIDE (.env.local — NOT committed to git):
# ─────────────────────────────────────────────────────────
# If Codespaces secrets are not set, you can also manually
# create .env.local in the workspace root and fill it in.
# The start-controller.sh script reads from .env.local.
#
# cp .env.example .env.local
# # Then edit .env.local with your values
