# syntax=docker/dockerfile:1

FROM rust:1.95-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY protocol/ protocol/
COPY ledger/ ledger/
COPY rules/ rules/
COPY agent/ agent/
WORKDIR /src/agent

FROM build AS test
RUN cargo test --package zedr-agent-shared --package zedr-agent-linux

FROM build AS release
RUN cargo build --release --package zedr-agent-linux

FROM scratch AS binary
COPY --from=release /src/agent/target/release/zedr-agent-linux /zedr-agent
