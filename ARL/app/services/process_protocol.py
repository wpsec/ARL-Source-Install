"""跨进程阶段的轻量输入、租约和缓存协议。

协议文件只保存阶段需要的最小元数据；锁和缓存均使用私有临时文件，避免
多个 worker 同时启动相同外部扫描，也避免把外部工具的完整命令写入协议。
"""

import hashlib
import json
import os
import tempfile
import time

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows worker 使用 fail-open 降级
    fcntl = None


def stable_process_key(namespace, *parts):
    payload = json.dumps(
        [str(namespace or "")] + list(parts),
        ensure_ascii=False,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:32]


def private_cache_path(root, namespace, key):
    directory = os.path.join(str(root), "arl-process-cache")
    os.makedirs(directory, mode=0o700, exist_ok=True)
    filename = "{}-{}.json".format(str(namespace or "process"), str(key or "")[:64])
    return os.path.join(directory, filename)


def write_private_json(file_path, payload):
    directory = os.path.dirname(file_path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".protocol-", suffix=".tmp", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, separators=(",", ":"))
        os.replace(temp_path, file_path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def read_private_json(file_path, max_age_sec=0):
    try:
        if not os.path.isfile(file_path):
            return None
        if max_age_sec and time.time() - os.path.getmtime(file_path) > float(max_age_sec):
            return None
        with open(file_path, "r", encoding="utf-8") as stream:
            value = json.load(stream)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, TypeError):
        return None


class ProcessLease(object):
    """基于 flock 的跨进程 lease；不支持 flock 的平台保持原有并发语义。"""

    def __init__(self, root, namespace, key):
        directory = os.path.join(str(root), "arl-process-lease")
        os.makedirs(directory, mode=0o700, exist_ok=True)
        self.path = os.path.join(
            directory,
            "{}-{}.lock".format(str(namespace or "process"), str(key or "")[:64]),
        )
        self._fd = None

    def acquire(self, wait_sec=0, sleep_sec=0.1):
        if fcntl is None:
            return True
        try:
            self._fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            deadline = time.monotonic() + max(0.0, float(wait_sec or 0))
            while True:
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return True
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        self.release()
                        return False
                    time.sleep(max(0.01, float(sleep_sec or 0.1)))
        except (OSError, TypeError, ValueError):
            self.release()
            return True

    def release(self):
        if self._fd is None:
            return
        fd = self._fd
        self._fd = None
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass

    def __enter__(self):
        if not self.acquire():
            raise RuntimeError("process lease unavailable")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()
        return False
