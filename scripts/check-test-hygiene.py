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
                # 还原收集失败真因：直接再 import 一次取异常摘要（否则只能看到
                # 无信息的 failed-test，无法区分"环境缺依赖"与"前缀/路径错误"）。
                detail = ""
                try:
                    __import__(name)
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
    )
    return proc


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
                    proc.kill()
                    dirty.append("%s\ttimeout\t?" % name)
                    print(dirty[-1])
                    continue
                still.append((name, proc, started))
                continue
            out, _ = proc.communicate(timeout=10)
            lines = (out or "").strip().splitlines()
            record = lines[-1] if lines else "%s\tno-output\t?" % name
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
