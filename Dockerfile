# Multi-stage Dockerfile for Eva CLI
FROM python:3.11-slim as builder

WORKDIR /app

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    ripgrep \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain for fastwalk extension
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy package metadata
COPY pyproject.toml README.md ./
COPY src/ src/
COPY rust/ rust/

# Build wheels and install
RUN python -m pip install --upgrade pip setuptools wheel maturin
RUN cd rust/eva_fastwalk && maturin build --release -o /app/dist
RUN python -m pip install /app/dist/*.whl
RUN python -m pip install .

# Final slim runtime image
FROM python:3.11-slim as runner

WORKDIR /workspace

# Install runtime dependencies (ripgrep, git)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ripgrep \
    && rm -rf /var/lib/apt/lists/*

# Copy installed site-packages and binaries from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/eva /usr/local/bin/eva

ENTRYPOINT ["eva"]
CMD ["--help"]
