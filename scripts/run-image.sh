#!/usr/bin/env bash
# Run container mounting current directory into /workspace
docker run --rm -it -v "$(pwd)":/workspace build-env bash
