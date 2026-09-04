"""
域名数据模型
"""
from .baseInfo import BaseInfo


class DomainInfo(BaseInfo):
    def __init__(self, domain, record, type, ips):
        self.record_list = record
        # 上游测绘/provider 会产出 "host:"（port 为空的拼接残渣），
        # 不收敛会在站点探测生成 https://host:/ 非法 URL、分裂缓存 key。
        self.domain = str(domain or "").strip().rstrip(":")
        self.type = type
        self.ip_list = ips

    def __eq__(self, other):
        if isinstance(other, DomainInfo):
            if self.domain == other.domain:
                return True

    def __hash__(self):
        return hash(self.domain)

    def _dump_json(self):
        item = {
            "domain": self.domain,
            "record": self.record_list,
            "type": self.type,
            "ips": self.ip_list
        }
        return item