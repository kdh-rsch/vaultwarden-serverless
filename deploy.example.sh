#!/usr/bin/env bash
# ==============================================================================
# Vaultwarden Serverless Deployment Script for GCP Cloud Run
# Optimized for Cloud Run Free Tier (Gen 1, scale-to-zero, 512MiB, max 1 instance)
# ==============================================================================
set -euo pipefail

# --- Configuration (Modify these before running) ---
SERVICE_NAME="vaultwarden"
REGION="us-west1"
IMAGE="ghcr.io/YOUR_GITHUB_ID/vaultwarden-serverless:latest"

# S3 / Backblaze B2 / Cloudflare R2 credentials
REPLICA_BUCKET="your-b2-bucket"
REPLICA_ENDPOINT="s3.us-west-004.backblazeb2.com" # Hostname without protocol
LITESTREAM_ACCESS_KEY_ID="your-key-id"
LITESTREAM_SECRET_ACCESS_KEY="your-app-key"
# REPLICA_REGION="us-west-004" # Optional for AWS S3

# Vaultwarden feature toggles
SIGNUPS_ALLOWED="true" # Set to false after creating your initial admin/user account
INVITATIONS_ALLOWED="true"
SHOW_PASSWORD_HINT="false"

# Optional: Base URL of your vault (Required for WebAuthn/Passkeys and custom domains)
# DOMAIN="https://vault.example.com"
DOMAIN="${DOMAIN:-}"

# Optional: Custom passphrase for AES-256-GCM RSA key encryption in S3.
# (If omitted, automatically derived from LITESTREAM_SECRET_ACCESS_KEY)
# RSA_PASSPHRASE="your-custom-passphrase"
RSA_PASSPHRASE="${RSA_PASSPHRASE:-}"

# Optional: Admin portal access token (Recommended: Argon2 PHC hash instead of plain text)
# Generate interactively using Vaultwarden's built-in hashing command:
#   docker run --rm -it vaultwarden/server:latest /vaultwarden hash
# Example output: '$argon2id$v=19$m=65536,t=3,p=4$q7...'
# ADMIN_TOKEN='$argon2id$v=19$m=65536,t=3,p=4$...'
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

# Startup and graceful shutdown timeouts
STARTUP_TIMEOUT="30s"
SHUTDOWN_TIMEOUT="10s"

# --- Safety Pre-flight Checks ---
if [[ "${IMAGE}" == *"YOUR_GITHUB_ID"* ]] || [[ "${REPLICA_BUCKET}" == "your-b2-bucket"* ]] || [[ "${LITESTREAM_ACCESS_KEY_ID}" == "your-key-id"* ]]; then
  echo "[ERROR] Please edit deploy.example.sh and replace placeholder credentials (IMAGE, REPLICA_BUCKET, LITESTREAM_*) before deploying." >&2
  exit 1
fi

# --- Assemble Environment Variables ---
ENV_FLAGS=(
  "--set-env-vars=REPLICA_BUCKET=${REPLICA_BUCKET}"
  "--set-env-vars=REPLICA_ENDPOINT=${REPLICA_ENDPOINT}"
  "--set-env-vars=LITESTREAM_ACCESS_KEY_ID=${LITESTREAM_ACCESS_KEY_ID}"
  "--set-env-vars=LITESTREAM_SECRET_ACCESS_KEY=${LITESTREAM_SECRET_ACCESS_KEY}"
  "--set-env-vars=SIGNUPS_ALLOWED=${SIGNUPS_ALLOWED}"
  "--set-env-vars=INVITATIONS_ALLOWED=${INVITATIONS_ALLOWED}"
  "--set-env-vars=SHOW_PASSWORD_HINT=${SHOW_PASSWORD_HINT}"
  "--set-env-vars=WEBSOCKET_ENABLED=false"
  "--set-env-vars=STARTUP_TIMEOUT=${STARTUP_TIMEOUT}"
  "--set-env-vars=SHUTDOWN_TIMEOUT=${SHUTDOWN_TIMEOUT}"
)

if [[ -n "${DOMAIN}" ]]; then
  ENV_FLAGS+=("--set-env-vars=DOMAIN=${DOMAIN}")
fi

if [[ -n "${RSA_PASSPHRASE}" ]]; then
  ENV_FLAGS+=("--set-env-vars=RSA_PASSPHRASE=${RSA_PASSPHRASE}")
fi

if [[ -n "${ADMIN_TOKEN}" ]]; then
  # Use custom delimiter ^@^ to prevent gcloud from misinterpreting commas in Argon2 hashes
  ENV_FLAGS+=("--set-env-vars=^@^ADMIN_TOKEN=${ADMIN_TOKEN}")
fi

# --- Deploy to Cloud Run ---
# Note: RSA key lifecycle is handled automatically by the Go Supervisor.
# On first boot, a 2048-bit RSA key is generated, AES-256-GCM encrypted,
# and stored in your S3 bucket (vaultwarden-db/rsa_key.pem.enc).
# On subsequent scale-to-zero cold starts, the key is restored and decrypted.
echo "[INFO] Deploying ${SERVICE_NAME} to Google Cloud Run (${REGION})..."

# 1. Gracefully taint the active revision (if running) to freeze SQLite writes and flush S3.
# The old container will disarm Vaultwarden & Litestream, enter a holding state, and return 503
# to any incoming requests until Cloud Run terminates it.
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" --region="${REGION}" --format="value(status.url)" 2>/dev/null || true)
if [[ -n "${SERVICE_URL}" ]]; then
  echo "[INFO] Tainting existing revision to disarm writes and flush S3 (${SERVICE_URL}/_supervisor/taint)..."
  curl -s -f -X POST "${SERVICE_URL}/_supervisor/taint" \
    -H "Authorization: Bearer ${LITESTREAM_SECRET_ACCESS_KEY}" \
    --max-time 15 || true
fi

# 2. Deploy new revision without routing traffic (prevents concurrent Litestream writers)
gcloud run deploy "${SERVICE_NAME}" \
  --image="${IMAGE}" \
  --region="${REGION}" \
  --platform="managed" \
  --allow-unauthenticated \
  --execution-environment="gen1" \
  --memory="512Mi" \
  --cpu="1" \
  --min-instances="0" \
  --max-instances="1" \
  --concurrency="80" \
  --timeout="60s" \
  --port="8080" \
  --no-traffic \
  --startup-probe="httpGet.path=/ready,httpGet.port=8080,periodSeconds=2,failureThreshold=20" \
  --liveness-probe="httpGet.path=/healthz,httpGet.port=8080,periodSeconds=10" \
  "${ENV_FLAGS[@]}"

# 3. Atomically shift 100% of live traffic to the latest revision
# This triggers graceful drain and explicit sync teardown on the previous instance.
echo "[INFO] Shifting 100% traffic to the latest revision (--to-latest)..."
gcloud run services update-traffic "${SERVICE_NAME}" \
  --region="${REGION}" \
  --to-latest

echo "[SUCCESS] Deployment completed safely. Check Cloud Run console for service URL."
