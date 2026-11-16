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

# The development simulator, for runs that need an endpoint the agent refuses to be. It is never served to endpoints.
FROM build AS simulator-release
RUN cargo build --release --package zedr-simulator

FROM alpine:3.22 AS simulator
COPY --from=simulator-release /src/agent/target/release/zedr-simulator /usr/local/bin/zedr-simulator
ENTRYPOINT ["/usr/local/bin/zedr-simulator"]
