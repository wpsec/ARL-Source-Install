"""
Web信息猎手记录数据模型

功能说明：
- 表示Web信息猎手（WIH）收集的单条记录
- 存储从网页中提取的信息片段
- 支持去重和序列化

主要属性：
- record_type: 记录类型（如 cookie、token、key 等）
- content: 记录内容
- source: 内容来源（如 localStorage、sessionStorage、response 等）
- site: 所属站点
- fnv_hash: 内容哈希值（用于去重）

说明：
- 通过 fnv_hash 实现记录去重
- 支持 JSON 序列化存储
- 用于 Web 指纹和隐藏信息的收集
"""


class WihRecord:
    def __init__(self, record_type, content, source, site, fnv_hash):
        self.recordType = record_type
        self.content = content
        self.source = source
        self.site = site
        self.fnv_hash = fnv_hash

    def __str__(self):
        return "{} {} {} {}".format(self.recordType, self.content, self.source, self.site)

    def __repr__(self):
        return "<WihRecord>" + self.__str__()

    def __eq__(self, other):
        return self.fnv_hash == other.fnv_hash

    def __hash__(self):
        return self.fnv_hash

    def dump_json(self):
        return {
            "record_type": self.recordType,
            "content": self.content,
            "site": self.site,
            "source": self.source,
            "fnv_hash": str(self.fnv_hash),
        }