#!/usr/bin/env bash
set -euo pipefail

IMAGE_PREFIX="${IMAGE_PREFIX:-arl-source-install-rust-verify}"
DOCKERFILE="${DOCKERFILE:-ARL/docker/Dockerfile}"
BUILD_CONTEXT="${BUILD_CONTEXT:-.}"
PROGRESS="${PROGRESS:-plain}"

if ! command -v docker >/dev/null 2>&1; then
    echo "[ERROR] docker command not found" >&2
    exit 127
fi
if ! docker info >/dev/null 2>&1; then
    echo "[ERROR] Docker daemon is unavailable" >&2
    exit 1
fi
if ! docker buildx version >/dev/null 2>&1; then
    echo "[ERROR] docker buildx is unavailable" >&2
    exit 1
fi

for platform in linux/amd64 linux/arm64; do
    suffix="${platform##*/}"
    image="${IMAGE_PREFIX}:${suffix}"
    echo "[INFO] build ${platform}: ${image}"
    docker buildx build \
        --platform "${platform}" \
        --file "${DOCKERFILE}" \
        --tag "${image}" \
        --load \
        --progress "${PROGRESS}" \
        "${BUILD_CONTEXT}"
    echo "[INFO] smoke test ${platform}: ${image}"
    docker run --rm --platform "${platform}" "${image}" \
        python3 /usr/local/share/arl/arl_accel_smoke_test.py
done

echo "[INFO] multi-architecture Rust smoke verification passed"
