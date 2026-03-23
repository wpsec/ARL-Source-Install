"""
WAF 主机查询接口工具函数回归测试。
"""
import unittest

try:
    from app.routes.waf_host import _parse_host_port
except ModuleNotFoundError:
    _parse_host_port = None


@unittest.skipIf(
    _parse_host_port is None,
    "运行依赖未安装，跳过 WAF 主机路由回归",
)
class TestWafHostRouteUtils(unittest.TestCase):
    """
    验证 WAF 主机路由的 URL 兼容解析逻辑。
    """

    def test_parse_host_port_handles_invalid_port_in_url(self):
        """
        last_url 端口非法时，不应抛异常且应保留协议默认端口。
        """
        ip, domain, port = _parse_host_port("mail.example.com", "http://mail.example.com:abc/login")

        self.assertEqual("", ip)
        self.assertEqual("mail.example.com", domain)
        self.assertEqual(80, port)

    def test_parse_host_port_handles_host_without_scheme(self):
        """
        无 scheme 的 host[:port] 形态应可解析域名。
        """
        ip, domain, port = _parse_host_port("oa.example.com", "oa.example.com:8443/path")

        self.assertEqual("", ip)
        self.assertEqual("oa.example.com", domain)
        self.assertEqual(8443, port)

    def test_parse_host_port_handles_ip_target(self):
        """
        IP 目标应识别为 ip 字段，且不抛异常。
        """
        ip, domain, port = _parse_host_port("1.2.3.4", "https://1.2.3.4/login")

        self.assertEqual("1.2.3.4", ip)
        self.assertEqual("", domain)
        self.assertEqual(443, port)


if __name__ == "__main__":
    unittest.main()
