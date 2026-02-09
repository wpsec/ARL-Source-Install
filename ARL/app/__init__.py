"""
应用初始化模块
================================================

该模块负责应用启动前的初始化配置
主要功能：
- 关闭不必要的警告信息
- 配置运行环境
"""
import warnings

# 关闭 Python 3.6 不再支持的警告
# 因为某些依赖库可能还在检查 Python 版本
warnings.filterwarnings("ignore", category=UserWarning,
                        message="Python 3.6 is no longer supported by the Python core team")

# 关闭 Celery 使用超级用户权限运行的警告
# Docker 容器中通常以 root 用户运行，此警告可忽略
warnings.filterwarnings("ignore", category=UserWarning,
                        message="You're running the worker with superuser privileges")


