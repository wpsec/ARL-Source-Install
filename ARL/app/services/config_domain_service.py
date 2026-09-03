"""配置域事务服务。

路由只负责 HTTP 参数和响应；配置文件读取、锁和持久化由这里统一处理，
避免不同配置域各自实现不一致的更新流程。
"""


class ConfigDomainService(object):
    """为配置域提供统一的读取、保存和原子更新边界。"""

    def __init__(self, config_center, path_resolver, lock, logger=None):
        self.config_center = config_center
        self.path_resolver = path_resolver
        self.lock = lock
        self.logger = logger

    def resolve_path(self):
        return self.path_resolver()

    def load(self, config_path=None):
        path = config_path or self.resolve_path()
        return path, self.config_center.load(path)

    def save(self, config_obj, validator=None):
        if callable(validator):
            validator(config_obj)

        path = self.resolve_path()
        with self.lock:
            persist_result = self.config_center.persist(path, config_obj)
        return path, persist_result

    def update(self, payload, merger, validator=None):
        """在同一把锁内完成读取、合并、校验和持久化。

        ``merger`` 只处理配置域业务规则，不能直接执行文件写入；这样可确保
        敏感字段合并、扫描配置校验和运行态刷新使用同一事务边界。
        """
        if not callable(merger):
            raise ValueError("配置更新缺少 merger")

        path = self.resolve_path()
        with self.lock:
            config_obj = self.config_center.load(path)
            updated_config = merger(config_obj, payload)
            if callable(validator):
                validator(updated_config)
            persist_result = self.config_center.persist(path, updated_config)

        return path, updated_config, persist_result
