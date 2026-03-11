#!/usr/bin/env bash
set -euo pipefail

# 自动递增 ARL/version.txt 的 patch 号（vMAJOR.MINOR.PATCH）。
# 用法：
#   scripts/bump-version.sh
#   scripts/bump-version.sh --stage

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT_DIR}/ARL/version.txt"
STAGE_FILE=0

if [[ "${1:-}" == "--stage" ]]; then
  STAGE_FILE=1
fi

if [[ ! -f "${VERSION_FILE}" ]]; then
  echo "version file not found: ${VERSION_FILE}" >&2
  exit 1
fi

CURRENT_RAW="$(tr -d '\r\n' < "${VERSION_FILE}")"
CURRENT="${CURRENT_RAW#v}"

if [[ ! "${CURRENT}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "invalid version format in ${VERSION_FILE}: ${CURRENT_RAW}" >&2
  exit 1
fi

MAJOR="${BASH_REMATCH[1]}"
MINOR="${BASH_REMATCH[2]}"
PATCH="${BASH_REMATCH[3]}"
NEXT_PATCH=$((PATCH + 1))
NEXT_VERSION="v${MAJOR}.${MINOR}.${NEXT_PATCH}"

printf "%s" "${NEXT_VERSION}" > "${VERSION_FILE}"

if [[ "${STAGE_FILE}" -eq 1 ]]; then
  git -C "${ROOT_DIR}" add "${VERSION_FILE}"
fi

echo "${CURRENT_RAW} -> ${NEXT_VERSION}"
