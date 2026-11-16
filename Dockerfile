# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS console
WORKDIR /src/control_server/frontend
COPY control_server/frontend/package.json control_server/frontend/package-lock.json ./
RUN npm ci
COPY control_server/frontend/ ./
RUN npm run build

FROM rust:1.95-bookworm AS server
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY protocol/ protocol/
WORKDIR /src/control_server/backend
COPY control_server/backend/Cargo.toml control_server/backend/Cargo.lock* ./
# Dependencies compile against a stub crate so this layer is reused until the manifest changes.
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && touch src/lib.rs \
    && cargo build --release \
    && rm -r src
COPY control_server/backend/src/ src/
COPY control_server/backend/migrations/ migrations/
# COPY keeps source mtimes that predate the stub build, so without the touch cargo would keep the stub.
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin zedr-control-server \
    && mkdir /data

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=server /src/control_server/backend/target/release/zedr-control-server ./
COPY --from=console /src/control_server/frontend/dist/ console/
COPY control_server/backend/binaries/ binaries/
COPY --from=server --chown=65532:65532 /data /data
ENV ZEDR_SERVER_HOST=0.0.0.0 \
    ZEDR_SERVER_PORT=7770 \
    ZEDR_BINARIES_DIR=/app/binaries \
    ZEDR_FRONTEND_DIST=/app/console
# SQLite spills large sorts to a temp directory, and /data is the only writable path.
ENV SQLITE_TMPDIR=/data
EXPOSE 7770
VOLUME ["/data"]
USER 65532:65532
ENTRYPOINT ["/app/zedr-control-server"]
