# syntax=docker/dockerfile:1

# The rule program comes from `make guest` through the build context named guest, so this build needs no RISC Zero toolchain.
FROM rust:1.95-alpine AS release
ARG TARGETARCH
RUN apk add --no-cache build-base
WORKDIR /src
COPY protocol/ protocol/
COPY ledger/ ledger/
COPY rules/ rules/
COPY prover/host/ prover/host/
COPY --from=guest zedr-guest.bin /guest/zedr-guest.bin
ENV ZEDR_GUEST_BIN=/guest/zedr-guest.bin
# GCC on arm64 calls atomics helpers that the static musl link does not provide, inlined atomics need none.
# The build folder lives in a cache, so a change to the prover does not compile the zkVM again.
RUN --mount=type=cache,id=zedr-prover-$TARGETARCH,target=/src/prover/host/target \
    if [ "$TARGETARCH" = "arm64" ]; then export CFLAGS=-mno-outline-atomics CXXFLAGS=-mno-outline-atomics; fi \
    && cargo build --release --locked --manifest-path prover/host/Cargo.toml \
    && cp prover/host/target/release/zedr-prover /zedr-prover

FROM scratch AS binary
COPY --from=release /zedr-prover /zedr-prover
