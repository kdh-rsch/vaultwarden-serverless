# Global build arguments
ARG LITESTREAM_VERSION=0.5.17

# Stage 1: Build static Go Supervisor binary with latest stable Go
FROM --platform=$BUILDPLATFORM golang:alpine AS go-builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -ldflags="-s -w" -o /bin/supervisor ./cmd/supervisor

# Stage 2: Extract Litestream binary
FROM litestream/litestream:${LITESTREAM_VERSION} AS litestream-bin

# Stage 3: Final runtime image based on official Vaultwarden
FROM vaultwarden/server:latest

# Hardened security defaults (Vaultwarden Hardening Guide)
ENV SHOW_PASSWORD_HINT=false
ENV SIGNUPS_ALLOWED=false

# Default port and serverless-friendly configuration
ENV PORT=8080
ENV INTERNAL_PORT=8081
ENV ROCKET_PORT=8081
ENV ROCKET_ADDRESS=127.0.0.1
ENV IP_HEADER=X-Real-IP
ENV WEBSOCKET_ENABLED=false
ENV DATA_FOLDER=/data
ENV I_REALLY_WANT_VOLATILE_STORAGE=true

# Copy binaries
COPY --from=litestream-bin /usr/local/bin/litestream /usr/local/bin/litestream
COPY --from=go-builder /bin/supervisor /entrypoint

# Create non-root user (vaultwarden: 1000:1000) and prepare writable directories
RUN groupadd -g 1000 vaultwarden && \
    useradd -u 1000 -g vaultwarden -s /bin/sh -m vaultwarden && \
    mkdir -p /data /tmp /etc/litestream && \
    touch /etc/litestream.yml && \
    chown -R 1000:1000 /data /tmp /etc/litestream /etc/litestream.yml

# Run as unprivileged user (UID/GID 1000) for least privilege container isolation
USER 1000:1000

# Container healthcheck for local Docker runtime and orchestrators
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/healthz || exit 1

# Entrypoint as Go Supervisor (PID 1)
ENTRYPOINT ["/entrypoint"]
