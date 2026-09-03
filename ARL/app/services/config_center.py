"""配置中心的文件持久化服务。"""


class ConfigCenterService(object):
    def __init__(self, file_store, refresh_runtime_config=None):
        self.file_store = file_store
        self.refresh_runtime_config = refresh_runtime_config

    def load(self, config_path):
        return self.file_store.load(config_path)

    def persist(self, config_path, config_obj):
        backup_path = self.file_store.backup(config_path)
        self.file_store.atomic_write(config_path, config_obj)
        runtime_refreshed = False
        if callable(self.refresh_runtime_config):
            runtime_refreshed = bool(self.refresh_runtime_config(force=True))
        return {
            "backup_path": backup_path,
            "runtime_refreshed": runtime_refreshed,
        }
