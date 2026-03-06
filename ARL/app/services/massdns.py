"""
高速DNS爆破工具
"""
from app import utils
from app.config import Config
import os
import subprocess

logger = utils.get_logger()


class MassDNS:
    def __init__(self, domains=None, mass_dns_bin=None,
                 dns_server=None, tmp_dir=None, wildcard_domain_ip=None, concurrent=0,
                 dns_resolvers=None):

        if wildcard_domain_ip is None:
            wildcard_domain_ip = []

        if concurrent == 0:
            concurrent = 100

        self.domains = domains
        self.tmp_dir = tmp_dir
        self.dns_server = dns_server
        self.domain_gen_output_path = os.path.join(tmp_dir,
                                                   "domain_gen_{}".format(utils.random_choices()))
        self.mass_dns_output_path = os.path.join(tmp_dir,
                                                 "mass_dns_{}".format(utils.random_choices()))
        self.mass_dns_bin = mass_dns_bin
        self.wildcard_domain_ip = wildcard_domain_ip
        self.concurrent = concurrent
        self.custom_dns_server_path = ""
        self.dns_resolvers = dns_resolvers or []

    def domain_write(self):
        """将域名写到文件"""
        cnt = 0
        with open(self.domain_gen_output_path, "w") as f:
            for domain in self.domains:
                domain = domain.strip()
                if not domain:
                    continue
                f.write(domain + "\n")
                cnt += 1

        logger.info("MassDNS dict {}".format(cnt))

    def mass_dns(self):
        """域名爆破"""
        command = [self.mass_dns_bin, "-q",
                   "-r {}".format(self.dns_server),
                   "-o S",
                   "-w {}".format(self.mass_dns_output_path),
                   "-s {}".format(self.concurrent),
                   self.domain_gen_output_path,
                   "--root"
                   ]

        logger.info(" ".join(command))
        try:
            completed = utils.exec_system(
                command,
                timeout=5 * 24 * 60 * 60,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except OSError as e:
            logger.warning("massdns exec failed {} error: {}".format(self.mass_dns_bin, e))
            return False

        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="ignore").strip() if completed.stderr else ""
            stdout = completed.stdout.decode("utf-8", errors="ignore").strip() if completed.stdout else ""
            logger.warning(
                "massdns run failed rc={} stderr={} stdout={}".format(
                    completed.returncode, stderr[:500], stdout[:500]
                )
            )
            return False

        return True

    def build_custom_dns_server_file(self):
        if not self.dns_resolvers:
            return

        clean_resolvers = []
        for resolver in self.dns_resolvers:
            if not isinstance(resolver, str):
                continue
            resolver = resolver.strip()
            if resolver:
                clean_resolvers.append(resolver)

        if not clean_resolvers:
            return

        custom_path = os.path.join(self.tmp_dir, "dns_server_{}".format(utils.random_choices()))
        with open(custom_path, "w", encoding="utf-8") as f:
            for resolver in clean_resolvers:
                f.write(resolver + "\n")

        self.custom_dns_server_path = custom_path
        self.dns_server = custom_path
        logger.info("MassDNS use custom dns_resolvers {}".format(",".join(clean_resolvers)))

    def parse_mass_dns_output(self):
        output = []
        with open(self.mass_dns_output_path, "r+", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                data = line.split(" ")
                if len(data) != 3:
                    continue
                domain, _type, record = data
                record = record.strip().strip(".")

                # 泛解析域名IP  直接过滤掉
                if record in self.wildcard_domain_ip:
                    continue

                item = {
                    "domain": domain.strip("."),
                    "type": _type,
                    "record": record
                }
                output.append(item)

        self._delete_file()
        return output

    def _delete_file(self):
        try:
            os.unlink(self.domain_gen_output_path)
            os.unlink(self.mass_dns_output_path)
            if self.custom_dns_server_path:
                os.unlink(self.custom_dns_server_path)
        except Exception as e:
            logger.warning(e)

    def run(self):
        self.domain_write()
        self.build_custom_dns_server_file()
        if not self.mass_dns():
            self._delete_file()
            return []

        if not os.path.exists(self.mass_dns_output_path):
            logger.warning("massdns output not found {}".format(self.mass_dns_output_path))
            self._delete_file()
            return []

        output = self.parse_mass_dns_output()
        return output


def mass_dns(based_domain, words, wildcard_domain_ip=None):
    if wildcard_domain_ip is None:
        wildcard_domain_ip = []

    domains = []
    is_fuzz_domain = "{fuzz}" in based_domain
    for word in words:
        word = word.strip()
        if word:
            if is_fuzz_domain:
                domains.append(based_domain.replace("{fuzz}", word))
            else:
                domains.append("{}.{}".format(word, based_domain))

    if not is_fuzz_domain:
        domains.append(based_domain)

    logger.info("start brute:{} words:{} wildcard_record:{}".format(
        based_domain, len(domains), ",".join(wildcard_domain_ip)))

    mass = MassDNS(domains, mass_dns_bin=Config.MASSDNS_BIN,
                   dns_server=Config.DNS_SERVER, tmp_dir=Config.TMP_PATH,
                   wildcard_domain_ip=wildcard_domain_ip, concurrent=Config.DOMAIN_BRUTE_CONCURRENT,
                   dns_resolvers=Config.DNS_RESOLVERS)

    return mass.run()
