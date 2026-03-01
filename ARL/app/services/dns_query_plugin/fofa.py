from app.services.dns_query import DNSQueryBase
from urllib.parse import urlparse
from app import utils
from app.utils import get_fld
from app.services.fofaClient import fofa_query


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "fofa"
        self.support_ip_query = True
        self.support_cert_query = True

    def _extract_domain(self, value):
        """
        从 FOFA 结果首列中提取域名（过滤 IP 目标）
        """
        host = str(value or "").strip()
        if not host:
            return ""

        hostname = ""
        if "://" in host:
            try:
                hostname = urlparse(host).hostname or ""
            except Exception:
                hostname = ""
        else:
            host = host.split("/")[0]
            hostname = host.split(":")[0]

        hostname = hostname.strip().lower().rstrip(".")
        if not hostname:
            return ""
        if utils.is_vaild_ip_target(hostname):
            return ""
        return hostname

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

    def sub_domains_by_ip(self, ip):
        """
        按IP查询FOFA资产并提取域名
        """
        query = 'ip="{}"'.format(ip)
        self.logger.debug("ip:{}, fofa query: {}".format(ip, query))

        data = fofa_query(query, 9999)
        results = []
        if isinstance(data, dict):
            if data['error']:
                raise Exception(data['errmsg'])

            for item in data.get("results", []):
                if not item:
                    continue
                domain_data = self._extract_domain(item[0])
                if domain_data:
                    results.append(domain_data)

        else:
            raise Exception(data)

        return list(set(results))

    def sub_domains_by_cert(self, cert):
        """
        按证书序列号查询 FOFA 资产并提取域名
        """
        serial_number = str(cert.get("serial_number") or "").strip()
        if not serial_number:
            return []

        query = 'cert.sn="{}"'.format(serial_number)
        self.logger.debug("cert_sn:{}, fofa query: {}".format(serial_number, query))

        data = fofa_query(query, 9999)
        results = []
        if isinstance(data, dict):
            if data['error']:
                raise Exception(data['errmsg'])

            for item in data.get("results", []):
                if not item:
                    continue
                domain_data = self._extract_domain(item[0])
                if domain_data:
                    results.append(domain_data)
        else:
            raise Exception(data)

        return list(set(results))
