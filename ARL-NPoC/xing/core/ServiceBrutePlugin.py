from xing.core.BasePlugin import BasePlugin
from xing.utils import random_choices, exec_system, load_file, append_file
from xing.conf import Conf
from xing.core import SchemeType
import logging
import os
import re
import platform
import shutil

class ServiceBrutePlugin(BasePlugin):
    def __init__(self):
        super(ServiceBrutePlugin, self).__init__()
        self.gen_user_file = None
        self.gen_pass_file = None
        self.delay_scheme = [SchemeType.SSH, SchemeType.RDP]
        self.ncrack_bin = self._resolve_ncrack_bin()

    @staticmethod
    def _normalize_arch(arch):
        arch = str(arch or "").strip().lower()
        alias_map = {
            "amd64": "x86_64",
            "arm64": "aarch64"
        }
        return alias_map.get(arch, arch)

    def _resolve_ncrack_bin(self):
        """
        检测 ncrack 是否可用。
        在 ARM 环境使用 x86_64 预编译二进制时会返回不可用，避免运行时报错。
        """
        ncrack_bin = shutil.which("ncrack")
        if not ncrack_bin:
            self.logger.warning("ncrack not found, skip service brute plugin")
            return ""

        arch = self._normalize_arch(platform.machine())
        # 当前仓库内置 ncrack 为 x86_64 版本，非 x86_64 环境默认禁用。
        if arch != "x86_64":
            self.logger.warning("ncrack is x86_64-only in current bundle, skip on arch={}".format(arch))
            return ""

        try:
            completed = exec_system([ncrack_bin, "-V"], timeout=8)
            if completed.returncode != 0:
                self.logger.warning("ncrack self-check failed rc={}, skip service brute".format(completed.returncode))
                return ""
        except Exception as e:
            self.logger.warning("ncrack self-check error {}, skip service brute".format(e))
            return ""

        return ncrack_bin

    def _gen_user_pass_file(self):
        user_list, pass_list = self.load_dict()
        self.logger.info("load auth pair {}".format(len(user_list)))
        random_str = random_choices(6)
        random_user_file = os.path.join(Conf.TEMP_DIR,  random_str + ".user.txt")
        random_pass_file = os.path.join(Conf.TEMP_DIR,  random_str + ".pass.txt")
        append_file(random_user_file, user_list)
        append_file(random_pass_file, pass_list)
        self.gen_user_file = random_user_file
        self.gen_pass_file = random_pass_file

        self.debug_lever = 0
        if Conf.LOGGER_LEVEL <= logging.DEBUG:
            self.debug_lever = 7

        self.max_connection_limit = 15
        self.connection_delay = 100
        self.timeout = 10*60*1000

        for scheme in self.delay_scheme:
            if scheme in self.scheme:
                self.connection_delay = 1500
                self.timeout = 20*60*1000
                continue

    def _crack_user_pass(self):
        if not self.ncrack_bin:
            return

        self._gen_user_pass_file()
        random_out_file = os.path.join(Conf.TEMP_DIR, random_choices(6) + ".out.txt")
        cmd = [
            self.ncrack_bin,
            "-oN", "'{}'".format(random_out_file),
            "-f",
            "-d{}".format(self.debug_lever),
            "-v",
            "-g cl=1,CL={},at=1,cd={}ms,cr=5,to={}ms".format(self.max_connection_limit,
                                                             self.connection_delay,
                                                             self.timeout),
            "--pairwise",
            "-U '{}'".format(self.gen_user_file),
            "-P '{}'".format(self.gen_pass_file),
            self.target
        ]

        exec_system(cmd)

        if not os.path.exists(random_out_file):
            self.logger.warning("ncrack output not found, skip target {}".format(self.target))
            if self.gen_pass_file and os.path.exists(self.gen_pass_file):
                os.unlink(self.gen_pass_file)
            if self.gen_user_file and os.path.exists(self.gen_user_file):
                os.unlink(self.gen_user_file)
            return

        lines = load_file(random_out_file)

        if os.path.exists(random_out_file):
            os.unlink(random_out_file)

        os.unlink(self.gen_pass_file)
        os.unlink(self.gen_user_file)

        for line in lines:
            if "credentials on" not in line:
                continue
            pattern = r"Discovered\s+credentials\s+on\s+([^\s]+)\s+'([^\']+)'\s+'([^\']+)'"
            matches = re.findall(pattern, line)
            if matches:
                item = {
                    "username": matches[0][1],
                    "password": matches[0][2]
                }
                return item



