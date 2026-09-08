#!/usr/bin/env python3
"""计划 5/6/7 的离线代码回归入口。

该命令只运行仓库内单测，不连接 Mongo、RabbitMQ、Web API 或外部目标；每个测试
模块单独启动 Python 进程，避免 bootstrap 类测试的模块缓存相互污染。
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARL_ROOT = ROOT / "ARL"

PLAN_TESTS = {
    "5": (
        "test_site_fingerprint_registry",
        "test_service_fingerprint_registry",
        "test_service_detection_registry",
        "test_unified_fingerprints_build",
        "test_fingerprint_wiring_fetchsite",
        "test_fingerprint_wiring_ip_task",
    ),
    "6": (
        "test_api_unified_models",
        "test_api_unified_parser",
        "test_api_unified_shadow",
        "test_api_candidate_registry",
        "test_compare_release_groups",
        "test_validate_wih_baseline",
    ),
    "7": (
        "test_target_profile",
        "test_evidence_graph",
        "test_evidence_graph_adapter",
        "test_response_registry_snapshot",
        "test_discovery_observation_snapshot",
        "test_wih_strategy",
        "test_controlled_verification_policy",
        "test_wih_endpoint_probe_cache",
        "test_wih_orchestrator",
    ),
}


def _run_test(module_name: str) -> int:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [sys.executable, "-m", "unittest", "-q", "test." + module_name]
    completed = subprocess.run(command, cwd=str(ARL_ROOT), env=env)
    state = "通过" if completed.returncode == 0 else "失败"
    print("[{}] {}".format(state, module_name))
    return completed.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description="运行计划5/6/7离线代码回归")
    parser.add_argument(
        "--plan",
        choices=("5", "6", "7", "all"),
        default="all",
        help="只运行一个计划，默认运行全部",
    )
    parser.add_argument(
        "--stop-on-failure",
        action="store_true",
        help="首个模块失败后立即停止",
    )
    args = parser.parse_args(argv)
    plan_names = ("5", "6", "7") if args.plan == "all" else (args.plan,)
    failed = []
    for plan_name in plan_names:
        print("计划 {} 离线代码回归".format(plan_name))
        for module_name in PLAN_TESTS[plan_name]:
            if _run_test(module_name):
                failed.append(module_name)
                if args.stop_on_failure:
                    break
        if failed and args.stop_on_failure:
            break
    if failed:
        print("失败模块: {}".format(", ".join(failed)), file=sys.stderr)
        return 1
    print("计划 {} 离线代码回归全部通过".format(",".join(plan_names)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
