# Operations & Disaster Recovery Guide

This guide covers production operations, disaster recovery, real-time push notifications, custom domains, and security best practices for running `vaultwarden-serverless` on Google Cloud Run.

---

## Table of Contents

1. [Real-Time Push Notifications (Serverless Alternative to WebSockets)](#1-real-time-push-notifications)
2. [Disaster Recovery & Local Database Restore](#2-disaster-recovery--local-database-restore)
3. [Point-in-Time Recovery (PITR)](#3-point-in-time-recovery-pitr)
4. [Decrypting Remote RSA Keys Locally](#4-decrypting-remote-rsa-keys-locally)
5. [WebAuthn, Passkeys & Custom Domains](#5-webauthn-passkeys--custom-domains)
6. [Safe Zero-Conflict Deployments](#6-safe-zero-conflict-deployments)
7. [Email & SMTP Configuration](#7-email--smtp-configuration)
8. [Data Durability & Ephemeral Storage Limitations](#8-data-durability--ephemeral-storage-limitations)
9. [Admin Token Security & Argon2 PHC Hashes](#9-admin-token-security--argon2-phc-hashes)
10. [Subpath / Subdir Deployment (Defense-in-Depth)](#10-subpath--subdir-deployment-defense-in-depth)
11. [Strict Host Validation & Scanner Mitigation](#11-strict-host-validation--scanner-mitigation)
12. [Non-Root Container Security](#12-non-root-container-security)

---

## 1. Real-Time Push Notifications

### The Problem with WebSockets on Serverless
In standard Vaultwarden deployments, live sync between browser extensions and mobile apps relies on persistent WebSockets (`WEBSOCKET_ENABLED=true`). On Google Cloud Run, persistent WebSocket connections keep the container permanently active, which prevents scale-to-zero and incurs continuous CPU billing.

### The Solution: Bitwarden Push Relay
Vaultwarden natively supports the official Bitwarden Push Notification service. When you create, edit, or delete an item in your vault:
1. Vaultwarden sends a lightweight webhook to Bitwarden's push relay (`push.bitwarden.com`).
2. Bitwarden relays the push notification via Apple APNs (iOS) and Google FCM (Android) directly to your devices.
3. Your mobile phone wakes up in the background and silently syncs the changes from your server.
4. **No persistent WebSocket connection is required**, allowing Cloud Run to immediately scale to zero after the sync request completes.

### Setup Instructions

1. **Obtain Push Installation Credentials:**
   - Visit [bitwarden.com/host](https://bitwarden.com/host/).
   - Enter your email address and select your region (**United States** or **European Union**).
   - Bitwarden will email you an **Installation ID** (UUID) and an **Installation Key**.

2. **Configure Cloud Run Environment Variables:**
   ```bash
   gcloud run services update vaultwarden \
     --region="us-west1" \
     --update-env-vars="PUSH_ENABLED=true" \
     --update-env-vars="PUSH_INSTALLATION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
     --update-env-vars="PUSH_INSTALLATION_KEY=xxxxxxxxxxxxxxxxxxxx"
   ```
   *(If you selected the European Union region, also set `PUSH_RELAY_URI=https://push.bitwarden.eu`)*.

3. **Verify Push Service:**
   Upon container boot, inspect the Cloud Run logs. You should see:
   ```json
   {"severity":"INFO","time":"...","component":"vaultwarden","target":"vaultwarden::api::notifications","message":"Push notification service started"}
   ```

---

## 2. Disaster Recovery & Local Database Restore

All database changes are replicated to your S3-compatible storage (Backblaze B2, Cloudflare R2, or AWS S3) in real time using Litestream. If your Cloud Run instance is deleted or Google Cloud suffers an outage, you can restore your database locally in seconds.

### Prerequisites

Install the [Litestream CLI](https://litestream.io/install/):
```bash
# macOS (Homebrew)
brew install litestream

# Linux (Debian/Ubuntu)
curl -L -o litestream.deb https://github.com/benbjohnson/litestream/releases/download/v0.5.17/litestream-v0.5.17-linux-amd64.deb
sudo dpkg -i litestream.deb
```

### Restore the Latest Database State

Set your storage credentials in your terminal:
```bash
export LITESTREAM_ACCESS_KEY_ID="your-access-key-id"
export LITESTREAM_SECRET_ACCESS_KEY="your-secret-access-key"
```

Restore the SQLite database directly from S3:
```bash
# Backblaze B2 example
litestream restore \
  -o ./vaultwarden-restored.sqlite3 \
  s3://your-bucket-name/vaultwarden-db/db.sqlite3?endpoint=s3.us-west-004.backblazeb2.com
```

### Inspecting Restored Data

You can verify the restored SQLite database using the standard `sqlite3` CLI:
```bash
sqlite3 ./vaultwarden-restored.sqlite3 "SELECT count(*) FROM ciphers;"
sqlite3 ./vaultwarden-restored.sqlite3 "SELECT email FROM users;"
```

---

## 3. Point-in-Time Recovery (PITR)

If an accidental deletion or database corruption occurs, Litestream allows restoring the database to any exact second within the retention window (default: 7 days / 168 hours).

Specify the target timestamp with `-timestamp` in RFC 3339 format:
```bash
litestream restore \
  -timestamp "2026-09-27T04:30:00Z" \
  -o ./vaultwarden-pitr.sqlite3 \
  s3://your-bucket-name/vaultwarden-db/db.sqlite3?endpoint=s3.us-west-004.backblazeb2.com
```

---

## 4. Decrypting Remote RSA Keys Locally

On first boot, the Go supervisor generates a 2048-bit RSA private key (`rsa_key.pem`) used to sign JWT authentication tokens. To prevent user logouts across cold starts, this key is encrypted with **AES-256-GCM** and backed up to S3 as `vaultwarden-db/rsa_key.pem.enc`.

### Key Derivation Specification
- **Algorithm:** AES-256-GCM (12-byte nonce, 16-byte authentication tag).
- **Key Derivation:** PBKDF2 with HMAC-SHA256, 100,000 iterations, 16-byte salt.
- **Passphrase:** `RSA_PASSPHRASE` (if specified), or falls back to `LITESTREAM_SECRET_ACCESS_KEY`.
- **Payload Layout:** `[16-byte Salt] + [12-byte Nonce] + [Ciphertext] + [16-byte Tag]`.

### Standalone Python Decryption Script
If you need to recover `rsa_key.pem` on your local workstation without running the Go supervisor:

```python
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Read encrypted key from disk
with open("rsa_key.pem.enc", "rb") as f:
    encrypted_blob = f.read()

passphrase = sys.argv[1].encode("utf-8")  # Passphrase or LITESTREAM_SECRET_ACCESS_KEY

salt = encrypted_blob[:16]
nonce = encrypted_blob[16:28]
ciphertext_and_tag = encrypted_blob[28:]

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
derived_key = kdf.derive(passphrase)

aesgcm = AESGCM(derived_key)
decrypted_pem = aesgcm.decrypt(nonce, ciphertext_and_tag, None)

with open("rsa_key.pem", "wb") as f:
    f.write(decrypted_pem)

print("Successfully decrypted rsa_key.pem")
```

---

## 5. WebAuthn, Passkeys & Custom Domains

> [!IMPORTANT]
> **Cryptographic Origin Binding in WebAuthn:**
> WebAuthn credentials (hardware security keys like YubiKey, biometric passkeys, Touch ID / Windows Hello) are cryptographically bound to the exact origin domain. If you register passkeys under `https://vaultwarden-xxx.a.run.app` and later connect a custom domain (`https://vault.example.com`), **all previously registered passkeys will permanently fail authentication**.

### Recommended Setup
1. Assign a custom domain to your Cloud Run service (via Cloud Run Domain Mappings, Google Cloud Load Balancer, or Cloudflare).
2. Set the `DOMAIN` environment variable to match your custom domain **before** registering any user accounts or security keys:
   ```bash
   gcloud run services update vaultwarden \
     --region="us-west1" \
     --update-env-vars="DOMAIN=https://vault.example.com"
   ```

---

## 6. Safe Zero-Conflict Deployments (TAINT & Disarm)

Cloud Run manages revisions independently, meaning during traffic migrations a newly provisioned container instance and an older container instance may temporarily coexist for several seconds. 

Because Litestream requires a single exclusive writer per SQLite database, having two active containers write to the same S3 path simultaneously can cause Write-Ahead Log (WAL) generation forks (Split-Brain).

### The TAINT / Drain Mechanism

To eliminate concurrency conflicts deterministically, the Go Supervisor embeds an administrative endpoint:
- **Endpoint:** `POST /_supervisor/taint`
- **Authentication:** `Authorization: Bearer <LITESTREAM_SECRET_ACCESS_KEY>` or `X-Supervisor-Token: <SECRET>`
- **Execution:**
  1. Sets internal state to `TAINTED`.
  2. The `/ready` probe immediately returns `503 Service Unavailable`, instructing Cloud Run to stop routing traffic to this instance.
  3. Any incoming proxy traffic receives `503 Service Unavailable (Retry-After: 5)`.
  4. Active in-flight requests are gracefully drained.
  5. Vaultwarden process is stopped via `SIGTERM` (SQLite writes frozen).
  6. Explicit Litestream sync flushes all remaining WAL frames to remote S3 and verifies `txid == replica_txid`.
  7. Litestream replication daemon is stopped.
  8. Returns `200 OK` with the confirmed sync transaction ID.
  9. The container remains running in a disarmed "holding sentinel" state until Cloud Run sends `SIGTERM` (with a 5-minute safety watchdog).

Because the old instance has completely shut down both Vaultwarden and Litestream, the new instance can safely restore from S3 and become the exclusive writer without any write contention or generation collisions.

### Safe Deployment Pattern

```bash
# 1. Gracefully taint the active revision (if running)
SERVICE_URL=$(gcloud run services describe vaultwarden --region="us-west1" --format="value(status.url)" 2>/dev/null || true)
if [[ -n "${SERVICE_URL}" ]]; then
  curl -s -f -X POST "${SERVICE_URL}/_supervisor/taint" \
    -H "Authorization: Bearer ${LITESTREAM_SECRET_ACCESS_KEY}" \
    --max-time 15 || true
fi

# 2. Deploy the new revision without routing traffic
gcloud run deploy vaultwarden \
  --image="ghcr.io/kdh-rsch/vaultwarden-serverless:latest" \
  --no-traffic \
  --region="us-west1"

# 3. Atomically shift 100% of live traffic to the latest revision
gcloud run services update-traffic vaultwarden \
  --region="us-west1" \
  --to-latest
```

When traffic shifts, Cloud Run delivers `SIGTERM` to the old revision. Since the old container is already tainted and disarmed, it exits in 0ms cleanly.

### On-Demand S3 Sync API (`POST /_supervisor/sync`)

To force an immediate, synchronous WAL flush to remote S3 without shutting down the service or entering maintenance mode:

```bash
curl -X POST "${SERVICE_URL}/_supervisor/sync" \
  -H "Authorization: Bearer ${LITESTREAM_SECRET_ACCESS_KEY}"
```

**Response (`200 OK`):**
```json
{
  "status": "synchronized",
  "message": "WAL frames successfully replicated and durable in remote S3",
  "db_path": "/data/db.sqlite3",
  "txid": 42,
  "replica_txid": 42,
  "duration_ms": 18
}
```

This endpoint allows external backup scripts, health monitors, or administrators to confirm remote replication durability on demand.

---

## 7. Email & SMTP Configuration

Configuring an SMTP service enables critical security notifications, two-factor authentication (2FA) email tokens, and new device login alerts.

### Recommended Environment Variables

```bash
gcloud run services update vaultwarden \
  --region="us-west1" \
  --update-env-vars="SMTP_HOST=smtp-relay.brevo.com" \
  --update-env-vars="SMTP_FROM=vault@example.com" \
  --update-env-vars="SMTP_FROM_NAME=Vaultwarden Security" \
  --update-env-vars="SMTP_PORT=587" \
  --update-env-vars="SMTP_SECURITY=starttls" \
  --update-env-vars="SMTP_USERNAME=your-smtp-login" \
  --update-env-vars="SMTP_PASSWORD=your-smtp-password" \
  --update-env-vars="SMTP_AUTH_MECHANISM=Plain"
```

### Free SMTP Providers Suitable for Personal Vaults
- **Brevo (formerly Sendinblue):** Free tier allows up to 300 emails/day.
- **Mailgun / SendGrid:** Free trial / developer tiers.
- **Gmail SMTP Relay:** Using a Google Account with an App Password (`smtp.gmail.com`, Port `587`).

---

## 8. Data Durability & Ephemeral Storage Limitations

> [!CAUTION]
> **Ephemeral Storage Notice:**
> - **Durable Data (Replicated to S3):** All credentials, logins, secure notes, credit cards, identities, TOTP seeds, organizations, collections, and user accounts stored in SQLite are continuously streamed to S3 and survive cold starts.
> - **Ephemeral Data (Not Replicated):** Binary file attachments (`/data/attachments`) and Bitwarden Send file drops (`/data/sends`) stored on the container filesystem are **temporary**. When Cloud Run scales to zero, local disk storage is reclaimed.
> - **Recommendation:** If you require binary file attachments, store sensitive files in an external encrypted cloud drive (e.g. Cryptomator with B2/R2) and link references in Vaultwarden secure notes.

---

## 9. Admin Token Security & Argon2 PHC Hashes

Upstream Vaultwarden has deprecated plain text strings for `ADMIN_TOKEN`. Plain text tokens risk exposure in container environment listings, Cloud Run revision histories, and server logs, and are susceptible to timing attacks.

To protect your admin portal (`/admin`), Vaultwarden requires or strongly recommends an **Argon2id PHC formatted string**.

### 1. Generating an Argon2 Hash

Generate an Argon2 hash interactively using Vaultwarden's built-in hashing command:

```bash
docker run --rm -it vaultwarden/server:latest /vaultwarden hash
```

When prompted, type your desired admin password and press Enter:
```text
Password: 
$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ...$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Alternatively, generate it using Python (`pip install argon2-cffi`):
```bash
python3 -c "
import argon2
ph = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)
print(ph.hash('YourSuperSecretAdminPassword'))
"
```

The output is formatted as an Argon2 PHC string:
```text
$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ...$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 2. Configuring on Google Cloud Run

Because the hash contains multiple `$` characters (e.g., `$argon2id$v=19`), bash will treat `$v` as an empty variable if wrapped in double quotes. Always wrap in **single quotes** or use Secret Manager.

#### Option A: Direct Environment Variable (Single Quotes)
```bash
gcloud run services update vaultwarden \
  --region="us-west1" \
  --update-env-vars='ADMIN_TOKEN=$argon2id$v=19$m=65536,t=3,p=4$...'
```

#### Option B: Google Secret Manager (Recommended)
```bash
# 1. Create the secret
echo -n '$argon2id$v=19$m=65536,t=3,p=4$...' | gcloud secrets create vaultwarden-admin-token --data-file=-

# 2. Attach to Cloud Run
gcloud run services update vaultwarden \
  --region="us-west1" \
  --set-secrets="ADMIN_TOKEN=vaultwarden-admin-token:latest"
```

### 3. Accessing the Admin Portal

Navigate to `https://your-vaultwarden-domain/admin`. When prompted, enter your plaintext password (`YourSuperSecretAdminPassword`). Vaultwarden cryptographically validates the password against the stored Argon2 PHC hash using constant-time verification.

---

## 10. Subpath / Subdir Deployment (Defense-in-Depth)

By default, Vaultwarden serves from the root of a domain (`https://vault.example.com/`). To protect against automated port scanners, Shodan indexing, and blind credential stuffers, you can host your instance under an obscure subpath (e.g. `https://vault.example.com/sec-vault-49x1/`).

### How It Works

Because scan bots typically target default endpoints such as `/`, `/api/accounts/login`, or `/admin`, placing Vaultwarden under an obscure subpath acts as an additional layer of defense-in-depth: requests to the root domain receive 404/403 errors, effectively making the instance invisible to indiscriminate internet scanners.

### Setup Instructions

1. **Configure Environment Variable:**
   Set `DOMAIN` with your desired subpath:
   ```bash
   gcloud run services update vaultwarden \
     --region="us-west1" \
     --update-env-vars="DOMAIN=https://vault.example.com/sec-vault-49x1"
   ```

2. **Configure Bitwarden Clients:**
   In your Bitwarden browser extension, desktop app, or mobile app:
   - On the login screen, click the **Gear (Settings)** icon.
   - Set **Server URL** to: `https://vault.example.com/sec-vault-49x1`
   - Log in normally. The client will direct all API calls to the configured subpath.

---

## 11. Strict Host Validation & Scanner Mitigation

To prevent attackers from discovering your Vaultwarden instance by scanning public IP ranges or hitting unintended hostnames, the embedded reverse proxy supports **Strict Host Validation**.

### How It Works

When strict host validation is active:
1. Every incoming HTTP request must match an allowed hostname (e.g. `vault.example.com`).
2. Requests with raw IP addresses in the `Host` header (e.g. `Host: 34.120.x.x`) or unauthorized hostnames are rejected with **`403 Forbidden`**.
3. A structured `WARNING` log entry is recorded with the offending `Host` header, path, and client IP.
4. **Cloud Run Health Probes** (`/healthz` and `/ready`) are processed before host validation, ensuring container health probes always succeed even when Google sends internal probe host headers.

### Configuration

#### Method 1: Automatic Derivation from `DOMAIN` (Recommended)
Set `STRICT_HOST=true`. The supervisor will automatically extract the hostname from your `DOMAIN` variable:
```bash
gcloud run services update vaultwarden \
  --region="us-west1" \
  --update-env-vars="DOMAIN=https://vault.example.com" \
  --update-env-vars="STRICT_HOST=true"
```

#### Method 2: Explicit Host Whitelist
Set `ALLOWED_HOSTS` to a comma-separated list of allowed hostnames:
```bash
gcloud run services update vaultwarden \
  --region="us-west1" \
  --update-env-vars="ALLOWED_HOSTS=vault.example.com,vault-internal.corp.com"
```

---

## 12. Non-Root Container Security

The `vaultwarden-serverless` container is engineered following the **Principle of Least Privilege** and CIS Docker Benchmark standards:

1. **Unprivileged User Execution (`USER 1000:1000`):**
   - The Go supervisor (PID 1), Litestream replication daemon, and Vaultwarden server all execute under an unprivileged user (`vaultwarden`, UID/GID `1000:1000`).
   - The container operates entirely on non-privileged ports (`PORT=8080`, `INTERNAL_PORT=8081`), eliminating the need for `CAP_NET_BIND_SERVICE` or root privileges.
   - In the event of a theoretical remote code execution vulnerability in native C dependencies (SQLite, OpenSSL), the attacker cannot compromise the container root or host kernel.

2. **Access Log Query Redaction:**
   - Web-Vault and mobile notification connections transmit tokens via query parameters (e.g. `GET /notifications/hub?access_token=[JWT]`).
   - The embedded reverse proxy automatically sanitizes query parameters (`access_token`, `token`, `key`, `secret`, `password`, `api_key`), redacting them to `[REDACTED]` before writing to Google Cloud Logging.

3. **Secure Defaults:**
   - Master password hints are disabled by default (`SHOW_PASSWORD_HINT=false`) to protect against password-guessing attacks.
   - New user registration is disabled by default in the image (`SIGNUPS_ALLOWED=false`), requiring explicit administrator opt-in.


