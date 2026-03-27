#!/usr/bin/env bash
set -euo pipefail

# 自动检查并同步 tools/poc 文库。
# 目标：让 start.sh / quick-build.sh 维持“一键部署”，避免用户手工单独下载。
#
# 可用环境变量（可写到 .env）：
#   ARL_POC_DIR                 PoC 文库目录（默认: <repo>/tools/poc）
#   ARL_POC_AUTO_SYNC_ENABLE    是否自动同步（默认: 1）
#   ARL_POC_REQUIRED            缺失时是否阻断启动（默认: 0）
#   ARL_POC_MIN_FILES           判定文库有效的最小文件数（默认: 50）
#   ARL_POC_ARCHIVE_PATH        本地压缩包路径（.tar.gz/.tgz/.tar.xz/.tar.zst/.zip）
#   ARL_POC_ARCHIVE_URL         远程压缩包 URL（支持 curl / wget）
#   ARL_POC_ARCHIVE_SUBDIR      压缩包内实际 PoC 子目录（可选）
#   ARL_POC_GIT_REPO            Git 仓库地址（归档源不可用时兜底）
#   ARL_POC_GIT_REF             Git 分支/Tag（可选）
#   ARL_POC_GIT_SUBDIR          Git 仓库中的 PoC 子目录（可选）

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

POC_DIR="${ARL_POC_DIR:-${ROOT_DIR}/tools/poc}"
AUTO_SYNC_ENABLE="${ARL_POC_AUTO_SYNC_ENABLE:-1}"
POC_REQUIRED="${ARL_POC_REQUIRED:-0}"
POC_MIN_FILES="${ARL_POC_MIN_FILES:-50}"

POC_ARCHIVE_PATH_RAW="${ARL_POC_ARCHIVE_PATH:-}"
POC_ARCHIVE_URL="${ARL_POC_ARCHIVE_URL:-}"
POC_ARCHIVE_SUBDIR="${ARL_POC_ARCHIVE_SUBDIR:-}"

POC_GIT_REPO="${ARL_POC_GIT_REPO:-}"
POC_GIT_REF="${ARL_POC_GIT_REF:-}"
POC_GIT_SUBDIR="${ARL_POC_GIT_SUBDIR:-}"

sanitize_positive_int() {
  local value="$1"
  local fallback="$2"
  if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -gt 0 ]; then
    echo "$value"
    return 0
  fi
  echo "$fallback"
}

POC_MIN_FILES="$(sanitize_positive_int "$POC_MIN_FILES" "50")"

resolve_path() {
  local raw="$1"
  if [ -z "$raw" ]; then
    echo ""
    return 0
  fi
  if [[ "$raw" = /* ]]; then
    echo "$raw"
  else
    echo "$ROOT_DIR/$raw"
  fi
}

count_poc_files() {
  if [ ! -d "$POC_DIR" ]; then
    echo 0
    return 0
  fi
  find "$POC_DIR" -type f | wc -l | tr -d ' '
}

is_poc_ready() {
  local file_count
  file_count="$(count_poc_files)"
  [ "$file_count" -ge "$POC_MIN_FILES" ]
}

copy_tree() {
  local src_dir="$1"
  local dst_dir="$2"

  mkdir -p "$dst_dir"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a "$src_dir/" "$dst_dir/"
  else
    cp -a "$src_dir/." "$dst_dir/"
  fi
}

extract_archive_to_poc() {
  local archive_path="$1"
  local tmp_dir
  tmp_dir="$(mktemp -d)"

  cleanup_tmp() {
    rm -rf "$tmp_dir" >/dev/null 2>&1 || true
  }
  trap cleanup_tmp RETURN

  case "$archive_path" in
    *.tar.gz|*.tgz)
      tar -xzf "$archive_path" -C "$tmp_dir"
      ;;
    *.tar.xz)
      tar -xJf "$archive_path" -C "$tmp_dir"
      ;;
    *.tar.zst|*.tzst)
      if tar --help 2>/dev/null | grep -qi 'zstd'; then
        tar --zstd -xf "$archive_path" -C "$tmp_dir"
      elif command -v unzstd >/dev/null 2>&1; then
        unzstd -c "$archive_path" | tar -xf - -C "$tmp_dir"
      elif command -v zstd >/dev/null 2>&1; then
        zstd -dc "$archive_path" | tar -xf - -C "$tmp_dir"
      else
        echo "[WARN] 无法解压 $archive_path（缺少 zstd/unzstd 支持）"
        return 1
      fi
      ;;
    *.zip)
      if command -v unzip >/dev/null 2>&1; then
        unzip -q "$archive_path" -d "$tmp_dir"
      else
        echo "[WARN] 无法解压 $archive_path（系统未安装 unzip）"
        return 1
      fi
      ;;
    *)
      echo "[WARN] 不支持的压缩包格式: $archive_path"
      return 1
      ;;
  esac

  local src_dir=""
  if [ -n "$POC_ARCHIVE_SUBDIR" ]; then
    src_dir="$tmp_dir/$POC_ARCHIVE_SUBDIR"
  else
    local top_dirs
    top_dirs="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    local top_files
    top_files="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')"
    if [ "$top_dirs" -eq 1 ] && [ "$top_files" -eq 0 ]; then
      src_dir="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d | head -n1)"
    else
      src_dir="$tmp_dir"
    fi
  fi

  if [ ! -d "$src_dir" ]; then
    echo "[WARN] 压缩包内未找到有效目录: $src_dir"
    return 1
  fi

  copy_tree "$src_dir" "$POC_DIR"
  return 0
}

sync_from_local_archive() {
  local archive_path
  archive_path="$(resolve_path "$POC_ARCHIVE_PATH_RAW")"
  [ -n "$archive_path" ] || return 1
  [ -f "$archive_path" ] || return 1

  echo "[INFO] 尝试从本地压缩包同步 PoC: $archive_path"
  extract_archive_to_poc "$archive_path"
}

sync_from_remote_archive() {
  [ -n "$POC_ARCHIVE_URL" ] || return 1

  local tmp_archive
  tmp_archive="$(mktemp)"
  local download_ok=0

  if command -v curl >/dev/null 2>&1; then
    if curl -fsSL --connect-timeout 10 --retry 2 "$POC_ARCHIVE_URL" -o "$tmp_archive"; then
      download_ok=1
    fi
  elif command -v wget >/dev/null 2>&1; then
    if wget -q -O "$tmp_archive" "$POC_ARCHIVE_URL"; then
      download_ok=1
    fi
  fi

  if [ "$download_ok" -ne 1 ]; then
    rm -f "$tmp_archive" >/dev/null 2>&1 || true
    return 1
  fi

  echo "[INFO] 尝试从远程压缩包同步 PoC: $POC_ARCHIVE_URL"
  if extract_archive_to_poc "$tmp_archive"; then
    rm -f "$tmp_archive" >/dev/null 2>&1 || true
    return 0
  fi

  rm -f "$tmp_archive" >/dev/null 2>&1 || true
  return 1
}

sync_from_git_repo() {
  [ -n "$POC_GIT_REPO" ] || return 1
  command -v git >/dev/null 2>&1 || return 1

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  local clone_dir="$tmp_dir/repo"
  local -a clone_cmd
  clone_cmd=(git clone --depth 1)
  if [ -n "$POC_GIT_REF" ]; then
    clone_cmd+=(--branch "$POC_GIT_REF")
  fi
  clone_cmd+=("$POC_GIT_REPO" "$clone_dir")

  echo "[INFO] 尝试从 Git 仓库同步 PoC: $POC_GIT_REPO"
  if ! "${clone_cmd[@]}" >/dev/null 2>&1; then
    rm -rf "$tmp_dir" >/dev/null 2>&1 || true
    return 1
  fi

  local src_dir="$clone_dir"
  if [ -n "$POC_GIT_SUBDIR" ]; then
    src_dir="$clone_dir/$POC_GIT_SUBDIR"
  fi

  if [ ! -d "$src_dir" ]; then
    rm -rf "$tmp_dir" >/dev/null 2>&1 || true
    return 1
  fi

  copy_tree "$src_dir" "$POC_DIR"
  rm -rf "$tmp_dir" >/dev/null 2>&1 || true
  return 0
}

finalize_result() {
  local count
  count="$(count_poc_files)"
  if [ "$count" -ge "$POC_MIN_FILES" ]; then
    echo "[INFO] PoC 文库已就绪: $POC_DIR (files=$count)"
    return 0
  fi

  if [ "$POC_REQUIRED" = "1" ]; then
    echo "[ERROR] PoC 文库不可用且 ARL_POC_REQUIRED=1，终止。目录: $POC_DIR"
    return 1
  fi

  echo "[WARN] PoC 文库不可用（files=$count, required_min=$POC_MIN_FILES），将以降级模式继续。"
  echo "[WARN] 可在 .env 配置 ARL_POC_ARCHIVE_URL / ARL_POC_GIT_REPO 以实现自动补齐。"
  return 0
}

if is_poc_ready; then
  echo "[INFO] PoC 文库已存在，跳过同步: $POC_DIR (files=$(count_poc_files))"
  exit 0
fi

if [ "$AUTO_SYNC_ENABLE" != "1" ]; then
  echo "[INFO] ARL_POC_AUTO_SYNC_ENABLE=$AUTO_SYNC_ENABLE，跳过自动同步。"
  finalize_result
  exit $?
fi

echo "[INFO] 检测到 PoC 文库缺失或不完整，开始自动同步..."

mkdir -p "$POC_DIR"

if sync_from_local_archive && is_poc_ready; then
  finalize_result
  exit $?
fi

if sync_from_remote_archive && is_poc_ready; then
  finalize_result
  exit $?
fi

if sync_from_git_repo && is_poc_ready; then
  finalize_result
  exit $?
fi

finalize_result
exit $?
