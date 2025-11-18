# syntax=docker/dockerfile:1

FROM debian:bookworm-slim

# Install runtime and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-pip \
    python3-dev \
    bash \
    pkg-config \
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workdir

# Copy source code
COPY . .

# Setup runtime directory and permissions
RUN mkdir -p /var/run/runtime && \
    chmod +x install.sh scripts/* start_openplc.sh

# Clean any existing build artifacts to ensure clean Docker build
RUN rm -rf build/ venvs/ .venv/ 2>/dev/null || true

# Run installation script
RUN ./install.sh

# Expose webserver port
EXPOSE 8443

# Start OpenPLC Runtime
CMD ["bash", "./start_openplc.sh"]
