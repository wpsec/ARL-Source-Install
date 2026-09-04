"""计划5 第5阶段：ServiceFingerprintRegistry——Nmap/NPoC 结果的规范服务映射。

定位（05 §零.2 口径）：不重做 `_build_sniffer_targets` 门控（已投产），本层只做三件事：
1. canonical 归一：nmap service_name / npoc scheme → 规范服务名（别名表来自规范文件，
   硬编码 alias_map 降级为文件不可用时的兜底，不再双头维护演进）。
2. 证据与置信：npoc_scheme(100) > nmap_service_name(90) > nmap_product_hint > port_only(弱候选)；
   高层与低层结论冲突时取高层并把双方写入 conflict 证据，不静默覆盖。
3. 端口弱候选：端口映射只能给出 candidate（port_confidence=25），绝不确认服务。

失败语义：文件缺失/损坏 → ok=False，canonical 退化为"输入小写原样"（等同现状行为），
服务识别链路不因规范层故障中断——与站点 unified 不同，本层是增强面而非数据源面。
"""
import gzip
import json
import logging
import os
import threading

from app.config import Config

logger = logging.getLogger(__name__)

SUPPORTED_SERVICE_FORMATS = {"arl_service_fingerprint_v1"}

_service_registry_instance = None
_service_registry_lock = threading.Lock()


class ServiceFingerprintRegistry:
    def __init__(self, path):
        self.path = path
        self.ok = False
        self.load_error = ""
        self.alias_map = {}      # nmap service / npoc scheme(lower) -> {"name","priority","weight"}
        self.port_map = {}       # (proto, port) -> name
        self.confidence = {}     # npoc=100, nmap_service=90, port=25 等
        self._file_token = None
        self._load()

    def _load(self):
        try:
            if self.path.endswith(".gz"):
                with gzip.open(self.path, "rb") as f:
                    raw = f.read()
            else:
                with open(self.path, "rb") as f:
                    raw = f.read()
            doc = json.loads(raw.decode("utf-8"))
            meta = doc.get("meta", {})
            if meta.get("format") not in SUPPORTED_SERVICE_FORMATS:
                raise ValueError("unsupported format: {}".format(meta.get("format")))
            alias_map = {}
            port_map = {}
            for rule in doc.get("fingerprints", []):
                if not rule.get("enabled", True):
                    continue
                name = str(rule.get("name", "")).strip().lower()
                if not name:
                    continue
                for scheme in rule.get("matchers", {}).get("npoc_schemes", []):
                    alias_map[str(scheme).strip().lower()] = {"name": name, "priority": "npoc_scheme",
                                                              "weight": 100}
                for svc in rule.get("matchers", {}).get("nmap_service_names", []):
                    key = str(svc).strip().lower()
                    alias_map.setdefault(key, {"name": name, "priority": "nmap_service_name", "weight": 90})
                for product in rule.get("matchers", {}).get("nmap_product_hints", []):
                    alias_map.setdefault(str(product).strip().lower(), {"name": name, "priority": "nmap_product_version",
                                                                        "weight": 80})
                port_weight = int(rule.get("resolution", {}).get("port_confidence", 25))
                for transport in rule.get("transports", []):
                    for port in transport.get("ports", []):
                        port_map.setdefault((str(transport.get("proto", "tcp")), int(port)), (name, port_weight))
            self.alias_map = alias_map
            self.port_map = port_map
            self.ok = True
            self.load_error = ""
            logger.info("service fingerprint registry loaded aliases=%d port_hints=%d",
                        len(alias_map), len(port_map))
        except Exception as exc:
            self.ok = False
            self.load_error = "load_failed: {}".format(exc)
            logger.warning("service fingerprint registry unavailable (fallback passthrough): %s", exc)

    # ---------- 归一 ----------

    def canonical(self, raw_name):
        """nmap service / npoc scheme → 规范服务名。文件不可用时等价于 strip+lower（现状行为）。"""
        key = str(raw_name or "").strip().lower()
        if not key:
            return ""
        if not self.ok:
            return key
        hit = self.alias_map.get(key)
        return hit["name"] if hit else key

    def normalize_result(self, nmap_service="", nmap_product="", npoc_scheme="", port=None, proto="tcp"):
        """按 §六 优先级选举规范服务：npoc(100) > nmap service(90) > product(80) > port(25,弱候选)。

        无结论返回 service=""，由调用方保留 unknown/pending；低层与高层结论不一致时
        取高层并把不一致的低层写入 conflict.rejected，不静默丢证据。
        """
        candidates = []
        scheme_key = str(npoc_scheme or "").strip().lower()
        if scheme_key:
            candidates.append({"source": "npoc_scheme", "value": scheme_key,
                               "service": self._canonical_key(scheme_key), "weight": 100})
        nmap_key = str(nmap_service or "").strip().lower()
        if nmap_key:
            candidates.append({"source": "nmap_service_name", "value": nmap_key,
                               "service": self._canonical_key(nmap_key), "weight": 90})
        product_key = str(nmap_product or "").strip().lower()
        if product_key and self.ok:
            hit = self.alias_map.get(product_key)
            if hit:
                candidates.append({"source": "nmap_product_version", "value": product_key,
                                   "service": hit["name"], "weight": 80})

        if candidates:
            candidates.sort(key=lambda c: -c["weight"])
            chosen = candidates[0]
            rejected = [
                {"source": c["source"], "value": c["value"], "service": c["service"]}
                for c in candidates[1:] if c["service"] != chosen["service"]
            ]
            return {
                "service": chosen["service"],
                "confirmed": True,
                "confidence": chosen["weight"],
                "sources": [c["source"] for c in candidates if c["service"] == chosen["service"]],
                "conflict": {"chosen": chosen["source"], "rejected": rejected} if rejected else None,
            }

        if port is not None and self.ok:
            try:
                port_num = int(port)
            except (TypeError, ValueError):
                return {"service": "", "confirmed": False, "confidence": 0, "sources": [], "conflict": None}
            port_hit = self.port_map.get((str(proto or "tcp"), port_num))
            if port_hit:
                name, weight = port_hit
                # 端口号只能产生弱候选（05 §六 优先级4），绝不确认服务
                return {"service": name, "confirmed": False, "confidence": weight,
                        "sources": ["port_only"], "conflict": None}

        return {"service": "", "confirmed": False, "confidence": 0, "sources": [], "conflict": None}

    def _canonical_key(self, key):
        if not self.ok:
            return key
        hit = self.alias_map.get(key)
        return hit["name"] if hit else key


def get_service_registry():
    global _service_registry_instance
    path = str(getattr(Config, "SERVICE_FINGERPRINT_FILE", "") or "")
    with _service_registry_lock:
        if _service_registry_instance is None or _service_registry_instance.path != path:
            _service_registry_instance = ServiceFingerprintRegistry(path)
        return _service_registry_instance


def reset_service_registry_for_test():
    global _service_registry_instance
    with _service_registry_lock:
        _service_registry_instance = None
