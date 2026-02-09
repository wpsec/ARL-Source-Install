from app.services.dns_query import DNSQueryBase
from app.utils import get_fld
from app.services.fofaClient import fofa_query


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "fofa"

    def sub_domains(self, target):
        query = 'domain="{}"'.format(target)

        domain = get_fld(target)

        # Target 是非法域名
        if not domain:
            self.logger.warning("Invalid domain: {}".format(target))
            return []

        # 表示是子域名，需要用host 和 domain 一起查询
        if domain != target:
            query = 'host="{}" && domain="{}"'.format(target, domain)

        self.logger.debug("target:{}, fofa query: {}".format(target, query))

        data = fofa_query(query, 9999)
        results = []
        if isinstance(data, dict):
            if data['error']:
                raise Exception(data['error'])

            for item in data["results"]:
                domain_data = item[0]
                if "://" in domain_data:
                    domain_data = domain_data.split(":")[1].strip("/")

                results.append(domain_data.split(":")[0])

        else:
            raise Exception(data)

        return list(set(results))

