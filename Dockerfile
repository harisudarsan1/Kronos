# Stage 1: Builder
FROM rust:1.79-slim-bookworm as builder

# Arguments for target architecture and LLVM version
ARG TARGETARCH
ARG LLVM_VERSION=19

# Install required dependencies
RUN apt-get update && apt-get install --yes \
    build-essential \
    protobuf-compiler \
    pkg-config \
    musl-tools \
    clang \
    wget \
    lsb-release \
    software-properties-common \
    gnupg && \
    wget -O /tmp/llvm.sh https://apt.llvm.org/llvm.sh && \
    chmod +x /tmp/llvm.sh && \
    /bin/sh -c "/tmp/llvm.sh ${LLVM_VERSION} all"

# Set up Rust toolchain
RUN rustup default stable && \
    rustup install nightly && \
    rustup component add rust-src --toolchain nightly && \
    cargo install bpf-linker


WORKDIR /workspace


# Define the target architecture in Rust's convention
# RUN if [ "$TARGETARCH" = "amd64" ]; \
#     then echo "x86_64" >> arch; \
#     else echo "aarch64" >> arch; \
#     fi
RUN rustup target add x86_64-unknown-linux-musl

# Copy source code
COPY .  .
# COPY kronos-ebpf kronos-ebpf
# COPY xtask xtask
# COPY Cargo.toml Cargo.toml
# COPY Cargo.lock Cargo.lock
# COPY .cargo .cargo
# COPY crates  crates

# Set environment variables for linking
ENV LD_LIBRARY_PATH="/usr/lib/llvm-$LLVM_VERSION/lib"
ENV CC_aarch64_unknown_linux_musl="/usr/lib/llvm-$LLVM_VERSION/bin/clang"
ENV AR_aarch64_unknown_linux_musl="/usr/lib/llvm-$LLVM_VERSION/bin/llvm-ar"
ENV CC_x86_64_unknown_linux_musl="/usr/lib/llvm-$LLVM_VERSION/bin/clang"
ENV AR_x86_64_unknown_linux_musl="/usr/lib/llvm-$LLVM_VERSION/bin/llvm-ar"
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-Clink-self-contained=yes -Clinker=rust-lld"

RUN --mount=type=cache,target=/workspace/target/ \
    --mount=type=cache,target=/root/.cargo/registry \
    cargo xtask build-ebpf --release
RUN --mount=type=cache,target=/workspace/target/ \
    --mount=type=cache,target=/root/.cargo/registry \
    RUSTFLAGS=-Ctarget-feature=+crt-static cargo build \
    --workspace \
    --exclude ebpf \ 
    --release \
    --target=x86_64-unknown-linux-musl
RUN --mount=type=cache,target=/workspace/target/ \
    cp /workspace/target/x86_64-unknown-linux-musl/release/kronos /workspace/kronos

# Stage 2: Final Image
FROM alpine

# Metadata
LABEL org.opencontainers.image.source="https://github.com/HARI-124/Kronos"
LABEL org.opencontainers.image.licenses="APACHE:2.0"

# Working directory and copy binary
WORKDIR /opt/
COPY --from=builder /workspace/kronos /opt/kronos

# # Add licenses if needed
# # COPY kronos/LICENSE.GPL-2.0 /opt/kronos/LICENSE.GPL-2.0
# # COPY kronos/LICENSE.BSD-2-Clause /opt/kronos/LICENSE.BSD-2-Clause
ENV KUBECONFIG="/root/.kube/config"
ENV RUSTLOG="info"

# Entry point
ENTRYPOINT ["/opt/kronos/kronos"]
