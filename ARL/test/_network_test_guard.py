import os
import unittest


def legacy_network_test(test_case):
    """历史联网用例必须显式开启，避免默认回归触达未授权目标。"""
    return unittest.skipUnless(
        os.environ.get("ARL_RUN_LEGACY_NETWORK_TESTS") == "1",
        "历史网络集成测试默认关闭；请使用独立的授权目标回归",
    )(test_case)
