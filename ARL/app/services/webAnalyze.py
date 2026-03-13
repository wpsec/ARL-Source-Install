"""
Web内容分析
"""
import time
import json
from app import utils
from app.config import Config
from .baseThread import BaseThread
logger = utils.get_logger()


class WebAnalyze(BaseThread):
    def __init__(self, sites, concurrency=3):
        super().__init__(sites, concurrency = concurrency)
        self.analyze_map = {}
        try:
            self.phantomjs_bin = utils.get_phantomjs_bin(logger=logger)
        except Exception as e:
            logger.warning("get_phantomjs_bin failed {}, fallback skip site_identify".format(e))
            self.phantomjs_bin = ""

        if not self.phantomjs_bin:
            logger.warning("phantomjs unavailable, skip site_identify for current task")

    def work(self, site):
        if not self.phantomjs_bin:
            return

        cmd_parameters = [self.phantomjs_bin,
                          '--ignore-ssl-errors true',
                          '--ssl-protocol any',
                          '--ssl-ciphers ALL',
                          Config.DRIVER_JS ,
                          site
                          ]
        logger.debug("WebAnalyze=> {}".format(" ".join(cmd_parameters)))

        try:
            output = utils.check_output(cmd_parameters, timeout=20)
        except OSError as e:
            logger.warning("WebAnalyze run error {} {}".format(site, e))
            return

        if not output:
            logger.warning("WebAnalyze empty output {}".format(site))
            return

        output = output.decode('utf-8')
        self.analyze_map[site] = json.loads(output)["applications"]

    def run(self):
        t1 = time.time()
        logger.info("start WebAnalyze {}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        logger.info("end WebAnalyze elapse {}".format(elapse))
        return self.analyze_map


def web_analyze(sites, concurrency=3):
    s = WebAnalyze(sites, concurrency=concurrency)
    return s.run()



