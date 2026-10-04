# syntax=docker/dockerfile:1

# --- build stage ----------------------------------------------------------
FROM golang:1.24-alpine AS build

# Alpine provides musl; build-base provides the gcc toolchain for CGO.
RUN apk add --no-cache build-base
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# SQLCipher bundles its own AES crypto, so a fully static musl binary needs no
# OpenSSL. The Tailwind standalone build (web/input.css -> web/static/app.css)
# is wired in here in Phase 3, when templates and styles exist.
RUN CGO_ENABLED=1 go build -trimpath \
      -ldflags '-linkmode external -extldflags "-static" -s -w' \
      -o /out/caffeinated-clients .

# Seed /data owned by the non-root runtime uid so a named volume mounted there
# inherits the correct ownership.
RUN mkdir -p /out/data

# --- runtime stage --------------------------------------------------------
FROM gcr.io/distroless/static-debian12:non-root

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
