"""
互联网资产自动化收集系统 - 主应用入口
================================================

这是 ARL (Asset Reconnaissance Lighthouse) 系统的主入口文件
负责初始化 Flask 应用和注册所有的 API 路由命名空间

主要功能:
- 初始化 Flask 应用
- 配置 Flask-RESTX API 文档
- 注册所有业务模块的路由命名空间
- 配置 API 认证方式

作者: ARL Team
版本: 2.6
"""

from flask import Flask
from flask_restx import Api

from app import routes
from app.utils import arl_update

# 创建 Flask 应用实例
arl_app = Flask(__name__)
# 启用错误捆绑，将多个错误一次性返回
arl_app.config['BUNDLE_ERRORS'] = True

# API 认证配置 - 使用 Token 进行身份验证
authorizations = {
    "ApiKeyAuth": {
        "type": "apiKey",      # 认证类型：API Key
        "in": "header",        # Token 位置：请求头
        "name": "Token"        # 请求头字段名
    }
}

# 初始化 Flask-RESTX API
# prefix: API 路由前缀
# doc: API 文档路径
# title: API 文档标题
# description: API 描述信息
# security: 默认安全认证方式
# version: API 版本号
api = Api(
    arl_app, 
    prefix="/api", 
    doc="/api/doc", 
    title='互联网资产自动化收集系统 Backend API', 
    authorizations=authorizations,
    description='互联网资产自动化收集系统 - 用于快速侦察与目标关联的互联网资产，构建基础资产信息库', 
    security="ApiKeyAuth", 
    version="2.6"
)

# ==================== 注册所有业务模块的路由命名空间 ====================

# 任务管理相关
api.add_namespace(routes.task_ns)              # 任务管理
api.add_namespace(routes.task_fofa_ns)         # FOFA 任务
api.add_namespace(routes.scheduler_ns)         # 任务调度器

# 资产数据相关
api.add_namespace(routes.site_ns)              # 站点资产
api.add_namespace(routes.domain_ns)            # 域名资产
api.add_namespace(routes.ip_ns)                # IP 资产
api.add_namespace(routes.url_ns)               # URL 资产
api.add_namespace(routes.cert_ns)              # 证书资产
api.add_namespace(routes.service_ns)           # 服务资产

# 资产范围管理
api.add_namespace(routes.asset_scope_ns)       # 资产范围
api.add_namespace(routes.asset_domain_ns)      # 资产域名
api.add_namespace(routes.asset_ip_ns)          # 资产 IP
api.add_namespace(routes.asset_site_ns)        # 资产站点

# 安全相关
api.add_namespace(routes.vuln_ns)              # 漏洞管理
api.add_namespace(routes.poc_ns)               # PoC 管理
api.add_namespace(routes.npoc_service_ns)      # NPoC 服务
api.add_namespace(routes.fileleak_ns)          # 文件泄露

# 系统管理
api.add_namespace(routes.user_ns)              # 用户管理
api.add_namespace(routes.policy_ns)            # 策略配置
api.add_namespace(routes.fingerprint_ns)       # 指纹管理
api.add_namespace(routes.stat_finger_ns)       # 指纹统计

# 数据导出
api.add_namespace(routes.export_ns)            # 单项导出
api.add_namespace(routes.batch_export_ns)      # 批量导出

# GitHub 相关
api.add_namespace(routes.github_task_ns)              # GitHub 任务
api.add_namespace(routes.github_result_ns)            # GitHub 结果
api.add_namespace(routes.github_scheduler_ns)         # GitHub 调度器
api.add_namespace(routes.github_monitor_result_ns)    # GitHub 监控结果

# 其他功能
api.add_namespace(routes.image_ns)             # 图片管理
api.add_namespace(routes.console_ns)           # 控制台
api.add_namespace(routes.cip_ns)               # CIP 管理
api.add_namespace(routes.task_schedule_ns)     # 任务调度
api.add_namespace(routes.nuclei_result_ns)     # Nuclei 扫描结果
api.add_namespace(routes.wih_ns)               # WIH (Web Information Hunter) 
api.add_namespace(routes.asset_wih_ns)         # 资产 WIH

# 执行系统更新检查
arl_update()

# 应用入口 - 仅用于开发调试
if __name__ == '__main__':
    # 启动开发服务器
    # debug=True: 开启调试模式，代码修改后自动重载
    # port=5018: 监听端口
    # host="0.0.0.0": 监听所有网络接口
    arl_app.run(debug=True, port=5018, host="0.0.0.0")
