#!/usr/bin/env python3
"""测试卫生扫描（计划 1 余留项工具化）：找出运行后污染 app.* 槽位的测试文件。

每个 test_*.py 在独立子进程加载并完整执行，结束后检查 `app`/`app.services`/
`app.utils`/`app.config`/`app.modules` 槽位是否残留 fake/空壳（注入不还原）。
空壳判据与 `ARL/test/_api_unified_bootstrap.assert_no_shell_pollution` 同口径，
额外检出 fake utils/config/modules。

判定口径（Review P0 教训）：
- 模块名必须带 `test.` 前缀——裸 stem 在 test/ 为包的环境被解析为
  `unittest.loader._FailedTest`，"运行成功"但测试从未 import，槽位检查
  会对没跑过的文件恒判 clean（假绿）。
- `collect-error`、`_FailedTest`、`ran=0`、子进程无输出/超时一律记 dirty：
  "测不了"不等于"测过且干净"。

用法（仓库根）：
    python3 scripts/check-test-hygiene.py                  # 全量扫描
    python3 scripts/check-test-hygiene.py test_x test_y    # 指定模块（自动补前缀）
退出码：0=全部干净且全部可执行；1=存在污染或加载失败。
"""
import os
import signal
import subprocess
import sys
import time
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
ARL_ROOT = REPO_ROOT / "ARL"

CHECKER = r'''
import sys, unittest, io, contextlib
name = sys.argv[1]
sys.path.insert(0, ".")
buf = io.StringIO()
ran = "ran=?"
load_fail = ""
try:
    with contextlib.redirect_stderr(buf):
        suite = unittest.defaultTestLoader.loadTestsFromName(name)
        for child in suite:
            if child.__class__.__name__ == "_FailedTest":
                # unittest 已将收集异常保存在 _exception；优先读取它，避免
                # 首次 import 的半加载模块残留在 sys.modules 后掩盖真因。
                failure = getattr(child, "_exception", None)
                detail = ""
                if failure is not None:
                    lines = str(failure).strip().splitlines()
                    detail = lines[-1][:120] if lines else type(failure).__name__
                if not detail:
                    try:
                        __import__(name, fromlist=["*"])
                    except BaseException as import_exc:  # noqa: BLE001
                        detail = "%s:%s" % (type(import_exc).__name__, str(import_exc)[:90])
                load_fail = "load-fail(%s)" % (detail or getattr(child, "_testMethodName", "?"))
        if not load_fail:
            result = unittest.TextTestRunner(stream=buf, verbosity=0).run(suite)
            ran = "ran=%d fail=%d err=%d skip=%d" % (
                result.testsRun, len(result.failures),
                len(result.errors), len(result.skipped))
            if result.testsRun == 0:
                load_fail = "ran-zero"
except Exception as exc:
    load_fail = "collect-error:%s:%s" % (type(exc).__name__, str(exc)[:80])
bad = []
app = sys.modules.get("app")
if app is not None:
    path = str(getattr(app, "__file__", "") or "").replace("\\", "/")
    if not path.endswith("/app/__init__.py"):
        bad.append("app=fake-file")
    if not hasattr(app, "__path__"):
        bad.append("app=no-path")
svc = sys.modules.get("app.services")
if svc is not None and not hasattr(svc, "run_api_doc_scan"):
    bad.append("app.services=shell")
utils = sys.modules.get("app.utils")
if utils is not None and not hasattr(utils, "get_logger"):
    bad.append("app.utils=fake")
cfg = sys.modules.get("app.config")
if cfg is not None and not hasattr(cfg, "Config"):
    bad.append("app.config=fake")
mods = sys.modules.get("app.modules")
if mods is not None and not hasattr(mods, "WihRecord"):
    bad.append("app.modules=fake")
if load_fail:
    bad.append(load_fail)
print("%s\t%s\t%s" % (name, ran, ",".join(bad) if bad else "clean"))
'''


def run_one(name, env):
    proc = subprocess.Popen(
        [sys.executable, "-c", CHECKER, name],
        cwd=str(ARL_ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, env=env,
        start_new_session=(os.name == "posix"),
    )
    return proc


def _signal_process_tree(proc, sig):
    """向隔离的测试进程组发信号，并返回是否成功发出。"""
    try:
        if os.name == "posix":
            os.killpg(proc.pid, sig)
        elif sig == signal.SIGKILL:
            proc.kill()
        else:
            proc.terminate()
    except ProcessLookupError:
        # 父进程可能已自然退出；后续仍需 drain 管道确认子进程是否残留。
        return False
    except OSError:
        # 进程组状态变化或权限异常时交给后续 drain 逻辑判定是否仍可回收。
        return False
    return True


def _drain_process_output(proc):
    """回收父进程及其后代可能持有的管道；必要时升级为 SIGKILL。"""
    try:
        proc.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        _signal_process_tree(proc, signal.SIGKILL)
        try:
            proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            return False
        except (OSError, ProcessLookupError):
            return True
    except (OSError, ProcessLookupError):
        return True
    return True


def terminate_process_tree(proc):
    """终止超时测试及其子进程，避免残留进程继续占用资源。"""
    force_wait_failed = False
    _signal_process_tree(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _signal_process_tree(proc, signal.SIGKILL)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            force_wait_failed = True
    except ProcessLookupError:
        # 父进程已经退出，仍需继续 drain，不能因此跳过子进程清理。
        force_wait_failed = False
    drained = _drain_process_output(proc)
    return drained and not force_wait_failed


def collect_output(name, proc):
    """收集测试输出；父进程退出但后代持有管道时也必须进入回收路径。"""
    try:
        out, _ = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        cleaned = terminate_process_tree(proc)
        marker = "timeout" if cleaned else "timeout-cleanup-failed"
        return "%s\t%s\t?" % (name, marker)
    except (OSError, ProcessLookupError) as exc:
        return "%s\tcollect-error:%s:%s" % (
            name,
            type(exc).__name__,
            str(exc)[:80],
        )
    lines = (out or "").strip().splitlines()
    return lines[-1] if lines else "%s\tno-output\t?" % name


def main(argv):
    names = argv[1:]
    names = [n if n.startswith("test.") else "test." + n for n in names]
    if not names:
        names = sorted("test." + p.stem for p in (ARL_ROOT / "test").glob("test_*.py"))
    env = dict(os.environ, PYTHONPATH=".")
    parallel = max(1, int(os.environ.get("HYGIENE_JOBS", "10")))
    timeout_sec = float(os.environ.get("HYGIENE_TIMEOUT", "600"))
    dirty = []
    load_fails = []
    pending = []
    queue = list(names)

    while queue or pending:
        while queue and len(pending) < parallel:
            name = queue.pop(0)
            pending.append((name, run_one(name, env), time.monotonic()))
        time.sleep(0.2)
        still = []
        for name, proc, started in pending:
            if proc.poll() is None:
                if time.monotonic() - started > timeout_sec:
                    cleaned = terminate_process_tree(proc)
                    marker = "timeout" if cleaned else "timeout-cleanup-failed"
                    record = "%s\t%s\t?" % (name, marker)
                    dirty.append(record)
                    load_fails.append(record)
                    continue
                still.append((name, proc, started))
                continue
            record = collect_output(name, proc)
            if record.endswith("\tclean"):
                continue
            dirty.append(record)
            if "load-fail(" in record or "collect-error" in record or "no-output" in record or "timeout" in record:
                load_fails.append(record)
            else:
                print(record)
        pending = still

    polluted = [r for r in dirty if r not in load_fails]
    print("--- load-fails(环境不可执行，不计污染): %d" % len(load_fails))
    for record in load_fails:
        print("  " + record)
    print("--- scanned=%d polluted=%d load_fails=%d clean=%d" % (
        len(names), len(polluted), len(load_fails),
        len(names) - len(polluted) - len(load_fails)))
    return 1 if polluted or load_fails else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
