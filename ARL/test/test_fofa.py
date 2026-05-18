import unittest
from unittest.mock import patch
from app.services.fofaClient import fofa_query_result, fofa_query, FofaClient
from app.config import Config


class TestFofa(unittest.TestCase):
    @patch("app.services.fofaClient.utils.http_req")
    def test_fofa_search_all_accepts_page(self, mock_http_req):
        class FakeResponse:
            def json(self):
                return {"error": False, "results": []}

        mock_http_req.return_value = FakeResponse()
        client = FofaClient("user@example.com", "fake-key", page_size=50)

        client.fofa_search_all('domain="example.com"', page=2)

        self.assertEqual(client.param["page"], 2)
        self.assertEqual(client.param["size"], 50)

    def test_vip_level(self):
        if not Config.FOFA_KEY or not Config.FOFA_KEY:
            self.fail("please set fofa key in config-docker.yaml")

        client = FofaClient(Config.FOFA_EMAIL, Config.FOFA_KEY, page_size=300)
        info = client.info_my()

        vip_level_map = {
            "0": "注册用户",
            "1": "普通会员",
            "2": "高级会员",
            "3": "企业会员"
        }
        vip_level = str(info["vip_level"])

        print("当前用户: {}, 帐号类型:{} ".format(Config.FOFA_EMAIL, vip_level_map[vip_level]))

    def test_query(self):
        data = fofa_query('test', page_size=1)
        print(data)
        self.assertTrue(data["size"] >= 1)

    def test_query_result(self):
        results = fofa_query_result('ip="8.8.8.8" && port="53"', page_size=100)

        self.assertTrue(len(results) == 1)


if __name__ == '__main__':
    unittest.main()
