# Security Envelopes Docker Image
# Multi-stage build for optimized production image

# Stage 1: Build environment
FROM rust:1.70-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Lean
RUN curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh -s -- -y
ENV PATH="/root/.elan/bin:$PATH"

# Install Python dependencies
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy source code
WORKDIR /app
COPY . .

# Build Lean specifications
RUN lake build

# Build Rust components
RUN cargo build --release --target x86_64-unknown-linux-musl

# Build WASM modules
RUN cargo build --target wasm32-wasi --release

# Stage 2: Production image
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libc6-compat \
    python3 \
    py3-pip \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Copy binaries from builder
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/policyengine /usr/local/bin/
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/rbac-gen /usr/local/bin/
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/attest-verify /usr/local/bin/

# Copy WASM modules
COPY --from=builder /app/target/wasm32-wasi/release/*.wasm /usr/local/lib/policyengine/

# Copy Python bundle generator
COPY --from=builder /app/bundle /usr/local/lib/bundle
COPY --from=builder /app/requirements.txt /usr/local/lib/bundle/

# Copy specifications
COPY --from=builder /app/Spec /usr/local/share/security-envelopes/Spec

# Copy examples
COPY --from=builder /app/examples /usr/local/share/security-envelopes/examples

# Set ownership
RUN chown -R appuser:appgroup /usr/local/bin /usr/local/lib /usr/local/share

# Switch to non-root user
USER appuser

# Set environment variables
ENV POLICYENGINE_LOG_LEVEL=info
ENV POLICYENGINE_WASM_PATH=/usr/local/lib/policyengine
ENV POLICYENGINE_SPEC_PATH=/usr/local/share/security-envelopes/Spec

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Default command
CMD ["policyengine"] 