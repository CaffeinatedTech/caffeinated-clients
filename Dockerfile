# syntax=docker/dockerfile:1

# --- build stage ----------------------------------------------------------
FROM golang:1.24-alpine AS build

# Alpine provides musl; build-base provides the gcc toolchain for CGO, and
# wget fetches the Tailwind standalone CLI.
RUN apk add --no-cache build-base
WORKDIR /src

ARG VERSION=dev

# Tailwind standalone CLI (no Node). Pick the release matching the build arch.
ARG TAILWINDCSS_VERSION=v4.1.11
RUN arch="$(uname -m)"; \
    case "$arch" in \
      x86_64) tw=x64 ;; \
      aarch64|arm64) tw=arm64 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    wget -qO /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWINDCSS_VERSION}/tailwindcss-linux-${tw}"; \
    chmod +x /usr/local/bin/tailwindcss

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the single CSS file from the templates, then the static musl binary.
# SQLCipher bundles its own AES crypto, so no OpenSSL is needed.
RUN tailwindcss -i web/input.css -o web/static/app.css --minify
RUN CGO_ENABLED=1 go build -trimpath \
      -ldflags "-linkmode external -extldflags \"-static\" -s -w -X github.com/CaffeinatedTech/caffeinated-clients/web.BuildVersion=${VERSION}" \
      -o /out/caffeinated-clients .

# Seed /data owned by the non-root runtime uid so a named volume mounted there
# inherits the correct ownership.
RUN mkdir -p /out/data

# --- runtime stage --------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/caffeinated-clients /caffeinated-clients
COPY --from=build --chown=65532:65532 /out/data /data

ENV CCLIENTS_DATA_DIR=/data \
    CCLIENTS_LISTEN_ADDR=:8080
VOLUME ["/data"]
EXPOSE 8080

USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/caffeinated-clients", "--healthcheck"]

ENTRYPOINT ["/caffeinated-clients"]
