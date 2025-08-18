# Dockerfile
FROM debian:bookworm-slim

# Install gcc, make, and build-essential
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    make \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Default workdir (will be overwritten when mounting host dir)
WORKDIR /workspace
