"""
策略配置管理模块

功能：
- 策略信息查询
- 策略添加、更新、删除
- 策略配置管理

说明：
- 策略是扫描任务的配置模板
- 包含域名、IP、站点相关的扫描选项
- 支持PoC插件和暴力破解插件配置
- 可关联资产范围
"""
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app.modules import ErrorMsg
from app import utils
from bson import ObjectId
from flask_restx.fields import Nested, String, Boolean, List
from flask_restx.model import Model

ns = Namespace('policy', description="策略信息")

logger = get_logger()

# 策略查询字段
base_search_fields = {
    'name': fields.String(required=False, description="策略名称"),
    "_id": fields.String(description="策略ID")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLPolicy(ARLResource):
    """策略信息查询接口"""
    
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        查询策略信息
        
        参数：
            - name: 策略名称（模糊匹配）
            - _id: 策略ID
            - page: 页码（默认1）
            - size: 每页数量（默认10）
        
        返回：
            {
                "code": 200,
                "data": {
                    "items": [策略列表],
                    "total": 总数
                }
            }
        
        策略字段说明：
            - name: 策略名称
            - desc: 策略描述
            - policy: 配置详情（包含domain_config、ip_config、site_config等）
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='policy')

        return data


# ==================== 策略配置字段模型 ====================

# 域名相关配置选项
domain_config_fields = ns.model('domainConfig', {
    "domain_brute": fields.Boolean(description="域名爆破", default=True),
    "domain_brute_type": fields.String(description="域名爆破类型(big)", example="big"),
    "alt_dns": fields.Boolean(description="DNS字典智能生成", default=True),
    "arl_search": fields.Boolean(description="ARL 历史查询", default=True),
    "dns_query_plugin": fields.Boolean(description="域名插件查询", default=False)
})

# IP 相关配置选项
ip_config_fields = ns.model('ipConfig', {
    "port_scan": fields.Boolean(description="端口扫描", default=True),
    "port_scan_type": fields.String(description="端口扫描类型(test|top100|top1000|all|custom)", example="test"),
    "service_detection": fields.Boolean(description="服务识别", default=False),
    "os_detection": fields.Boolean(description="操作系统识别", default=False),
    "ssl_cert": fields.Boolean(description="SSL 证书获取", default=False),
    "skip_scan_cdn_ip": fields.Boolean(description="跳过 CDN IP扫描", default=True),  # 这个参数强制生效
    "port_custom": fields.String(description="自定义扫描端口", default="80,443"),  # 仅端口扫描类型为 custom 时生效
    "host_timeout_type": fields.String(description="主机超时时间类别（default|custom）", default="default"),
    "host_timeout": fields.Integer(description="主机超时时间(s)", default=900),
    "port_parallelism": fields.Integer(description="探测报文并行度", default=32),
    "port_min_rate": fields.Integer(description="最少发包速率", default=60)
})

# 站点相关配置选项
site_config_fields = ns.model('siteConfig', {
    "site_identify": fields.Boolean(description="站点识别", default=False),
    "site_capture": fields.Boolean(description="站点截图", default=False),
    "search_engines": fields.Boolean(description="搜索引擎调用", default=False),
    "site_spider": fields.Boolean(description="站点爬虫", default=False),
    "nuclei_scan": fields.Boolean(description="nuclei 扫描", default=False),
    "web_info_hunter": fields.Boolean(example=False, default=False, description="web JS 中的信息收集"),
})

# 资产组关联配置
scope_config_fields = ns.model('scopeConfig', {
    "scope_id": fields.String(description="资产分组 ID", default=""),
})

# 添加策略请求模型
add_policy_fields = ns.model('addPolicy', {
    "name": fields.String(required=True, description="策略名称"),
    "desc": fields.String(description="策略描述信息"),
    "policy": fields.Nested(ns.model("policy", {
        "domain_config": fields.Nested(domain_config_fields),
        "ip_config": fields.Nested(ip_config_fields),
        "site_config": fields.Nested(site_config_fields),
        "file_leak": fields.Boolean(description="文件泄漏", default=False),
        "npoc_service_detection": fields.Boolean(description="服务识别（纯python实现）", default=False),
        "poc_config": fields.List(fields.Nested(ns.model('pocConfig', {
            "plugin_name": fields.String(description="poc 插件名称ID", default=False),
            "enable": fields.Boolean(description="是否启用", default=True)
        }))),
        "brute_config": fields.List(fields.Nested(ns.model('bruteConfig', {
            "plugin_name": fields.String(description="poc 插件名称ID", default=False),
            "enable": fields.Boolean(description="是否启用", default=True)
        }))),
        "scope_config": fields.Nested(scope_config_fields)
    }, required=True)
                            )
})


@ns.route('/add/')
class AddARLPolicy(ARLResource):
    """策略添加接口"""

    @auth
    @ns.expect(add_policy_fields)
    def post(self):
        """
        添加新策略
        
        请求体：
            {
                "name": "策略名称",
                "desc": "策略描述",
                "policy": {
                    "domain_config": {...域名配置...},
                    "ip_config": {...IP配置...},
                    "site_config": {...站点配置...},
                    "file_leak": true/false,
                    "npoc_service_detection": true/false,
                    "poc_config": [{plugin_name, enable}],
                    "brute_config": [{plugin_name, enable}],
                    "scope_config": {scope_id}
                }
            }
        
        返回：
            操作结果
        
        说明：
        - domain_config: 域名扫描配置（爆破、DNS查询等）
        - ip_config: IP扫描配置（端口扫描、服务识别等）
        - site_config: 站点扫描配置（爬虫、截图、Nuclei扫描等）
        - poc_config: PoC插件配置列表
        - brute_config: 暴力破解插件配置列表
        - scope_config: 关联的资产范围ID
        
        注意：
        - 端口扫描类型为custom时需提供port_custom参数
        - port_custom格式：逗号分隔的端口列表（如"80,443,8080"）
        """
        args = self.parse_args(add_policy_fields)
        name = args.pop("name")
        policy = args.pop("policy", {})
        if policy is None:
            return utils.build_ret("Missing policy parameter", {})

        # 处理域名配置
        domain_config = policy.pop("domain_config", {})
        domain_config = self._update_arg(domain_config, domain_config_fields)
        
        # 处理IP配置
        ip_config = policy.pop("ip_config", {})
        port_scan_type = ip_config.get("port_scan_type", "test")
        if port_scan_type == "custom":
            # 自定义端口列表，验证格式
            port_custom = ip_config.get("port_custom", "80,443")
            port_list = utils.arl.build_port_custom(port_custom)
            if isinstance(port_list, str):
                return utils.build_ret(ErrorMsg.PortCustomInvalid, {"port_custom": port_list})

            ip_config["port_custom"] = ",".join(port_list)

        ip_config = self._update_arg(ip_config, ip_config_fields)

        # 处理站点配置
        site_config = policy.pop("site_config", {})
        site_config = self._update_arg(site_config, site_config_fields)

        # 处理PoC插件配置
        poc_config = policy.pop("poc_config", [])
        if poc_config is None:
            poc_config = []

        poc_config = _update_plugin_config(poc_config)
        if isinstance(poc_config, str):
            return utils.build_ret(poc_config, {})

        # 处理暴力破解插件配置
        brute_config = policy.pop("brute_config", [])
        if brute_config is None:
            brute_config = []
        brute_config = _update_plugin_config(brute_config)
        if isinstance(brute_config, str):
            return utils.build_ret(brute_config, {})

        # 处理其他配置
        file_leak = fields.boolean(policy.pop("file_leak", False))
        npoc_service_detection = fields.boolean(policy.pop("npoc_service_detection", False))
        desc = args.pop("desc", "")

        # 获取关联资产组的配置
        scope_config = policy.pop("scope_config", {})
        scope_config = self._update_arg(scope_config, scope_config_fields)

        # 构建完整的策略数据
        item = {
            "name": name,
            "policy": {
                "domain_config": domain_config,
                "ip_config": ip_config,
                "site_config": site_config,
                "poc_config": poc_config,
                "brute_config": brute_config,
                "file_leak": file_leak,
                "npoc_service_detection": npoc_service_detection,
                "scope_config": scope_config
            },
            "desc": desc,
            "update_date": utils.curr_date()
        }
        
        # 保存到数据库
        utils.conn_db("policy").insert_one(item)

        return utils.build_ret(ErrorMsg.Success, {"policy_id": str(item["_id"])})

    def _update_arg(self, arg_dict, default_module):
        """
        更新参数字典，使用默认值填充缺失项
        
        参数：
            arg_dict: 用户提供的参数字典
            default_module: 默认值模块定义
        
        返回：
            合并后的完整参数字典
        """
        # 获取默认值字典
        default_dict = get_dict_default_from_module(default_module)
        if arg_dict is None:
            return default_dict

        # 用户参数覆盖默认值
        default_dict.update(arg_dict)

        # 格式化每个参数值
        for x in default_dict:
            if x not in default_module:
                continue

            default_dict[x] = default_module[x].format(default_dict[x])

        return default_dict


def plugin_name_in_arl(name):
    """
    检查插件名称是否存在于ARL系统中
    
    参数：
        name: 插件名称
    
    返回：
        插件数据或None
    """
    query = {
        "plugin_name": name
    }
    item = utils.conn_db('poc').find_one(query)
    return item


def get_dict_default_from_module(module):
    """
    从模块定义中提取默认值字典
    
    参数：
        module: 字段模块定义
    
    返回：
        包含默认值的字典
    """
    ret = {}
    for x in module:
        v = module[x]
        ret[x] = None
        # 优先使用default值
        if v.default is not None:
            ret[x] = v.default

        # 如果有example值则使用example
        if v.example is not None:
            ret[x] = v.example

    return ret


# 删除策略请求模型
delete_policy_fields = ns.model('DeletePolicy', {
    'policy_id': fields.List(fields.String(required=True, description="策略ID", example="603c65316591e73dd717d176"))
})


@ns.route('/delete/')
class DeletePolicy(ARLResource):
    """策略删除接口"""
    
    @auth
    @ns.expect(delete_policy_fields)
    def post(self):
        """
        批量删除策略
        
        请求体：
            {
                "policy_id": ["策略ID1", "策略ID2", ...]
            }
        
        返回：
            操作结果
        
        说明：
        - 支持批量删除多个策略
        - 删除操作不可逆
        - 已被任务使用的策略也可以删除
        """
        args = self.parse_args(delete_policy_fields)
        policy_id_list = args.pop('policy_id')
        
        # 遍历删除每个策略
        for policy_id in policy_id_list:
            if not policy_id:
                continue
            utils.conn_db('policy').delete_one({'_id': ObjectId(policy_id)})

        return utils.build_ret(ErrorMsg.Success, {})


# 编辑策略请求模型
edit_policy_fields = ns.model('editPolicy', {
    'policy_id': fields.String(required=True, description="策略ID", example="603c65316591e73dd717d176"),
    'policy_data': fields.Nested(ns.model("policyData", {}))
})


@ns.route('/edit/')
class EditPolicy(ARLResource):
    """策略编辑接口"""
    
    @auth
    @ns.expect(edit_policy_fields)
    def post(self):
        """
        编辑现有策略
        
        请求体：
            {
                "policy_id": "策略ID",
                "policy_data": {
                    "name": "新策略名称",
                    "desc": "新描述",
                    "policy": {
                        "domain_config": {...},
                        "ip_config": {...},
                        ...
                    }
                }
            }
        
        返回：
            {
                "code": 200,
                "data": {
                    "data": 更新后的策略数据
                }
            }
        
        说明：
        - 只更新提供的字段，未提供的字段保持不变
        - policy_data支持部分更新
        - 允许更新的键：name, desc, policy及其所有子配置
        - PoC和暴力破解插件配置会自动验证
        """
        args = self.parse_args(edit_policy_fields)
        policy_id = args.pop('policy_id')
        policy_data = args.pop('policy_data', {})
        
        # 查询现有策略
        query = {'_id': ObjectId(policy_id)}
        item = utils.conn_db('policy').find_one(query)

        if not item:
            return utils.build_ret(ErrorMsg.PolicyIDNotFound, {})

        if not policy_data:
            return utils.build_ret(ErrorMsg.PolicyDataIsEmpty, {})

        # 获取允许更新的键列表
        allow_keys = gen_model_policy_keys(add_policy_fields["policy"])
        allow_keys.extend(["name", "desc", "policy"])

        # 更新策略字典
        item = change_policy_dict(item, policy_data, allow_keys)

        # 处理PoC插件配置
        poc_config = item["policy"].pop("poc_config", [])
        poc_config = _update_plugin_config(poc_config)
        if isinstance(poc_config, str):
            return utils.build_ret(poc_config, {})
        item["policy"]["poc_config"] = poc_config

        # 处理暴力破解插件配置
        brute_config = item["policy"].pop("brute_config", [])
        brute_config = _update_plugin_config(brute_config)
        if isinstance(brute_config, str):
            return utils.build_ret(brute_config, {})
        item["policy"]["brute_config"] = brute_config

        # 更新时间戳并保存
        item["update_date"] = utils.curr_date()
        utils.conn_db('policy').find_one_and_replace(query, item)
        item.pop('_id')

        return utils.build_ret(ErrorMsg.Success, {"data": item})


def _update_plugin_config(config):
    """
    更新插件配置列表
    
    参数：
        config: 插件配置列表 [{plugin_name, enable}, ...]
    
    返回：
        处理后的插件配置列表或错误消息字符串
    
    说明：
    - 验证插件名称是否存在
    - 去重处理
    - 添加漏洞名称等附加信息
    """
    plugin_name_set = set()
    ret = []
    for item in config:
        plugin_name = str(item.get("plugin_name", ""))
        enable = item.get("enable", False)
        if plugin_name is None or enable is None:
            continue
        # 去重
        if plugin_name in plugin_name_set:
            continue

        # 验证插件是否存在
        plugin_info = plugin_name_in_arl(plugin_name)
        # 验证插件是否存在
        plugin_info = plugin_name_in_arl(plugin_name)
        if not plugin_info:
            return "没有找到 {} 插件".format(plugin_name)

        # 构建插件配置项
        config_item = {
            "plugin_name": plugin_name,
            "vul_name": plugin_info["vul_name"],
            "enable": bool(enable)
        }
        plugin_name_set.add(plugin_name)
        ret.append(config_item)

    return ret


def change_policy_dict(old_data, new_data, allow_keys):
    """
    递归更新策略字典（支持部分更新）
    
    参数：
        old_data: 旧的策略数据字典
        new_data: 新的策略数据字典
        allow_keys: 允许更新的键列表
    
    返回：
        更新后的字典
    
    说明：
    - 递归处理嵌套字典
    - 只更新allow_keys中的键
    - 对于列表类型，直接替换
    - 对于相同类型的值，直接替换
    """
    if not isinstance(new_data, dict):
        return

    for key in new_data:
        # 只处理允许的键
        if key not in allow_keys:
            continue

        next_old_data = old_data.get(key)
        next_new_data = new_data[key]
        
        # 如果旧数据中没有这个键，直接添加
        if next_old_data is None:
            old_data[key] = next_new_data
            continue

        next_new_data_type = type(next_new_data)
        next_old_data_type = type(next_old_data)

        # 递归处理嵌套字典
        if isinstance(next_old_data, dict):
            change_policy_dict(next_old_data, next_new_data, allow_keys)

        # 列表类型直接替换
        elif isinstance(next_old_data, list) and isinstance(next_new_data, list):
            old_data[key] = next_new_data

        # 相同类型的值直接替换
        elif next_new_data_type == next_old_data_type:
            old_data[key] = next_new_data

    return old_data


def gen_model_policy_keys(model):
    """
    递归生成策略模型的所有键名列表
    
    参数：
        model: Flask-RESTX模型定义
    
    返回：
        所有键名的列表
    
    说明：
    - 用于生成允许更新的键列表
    - 递归处理嵌套模型
    - 支持Model和Nested类型
    """
    if isinstance(model, Model):
        keys = []
        for name in model:
            keys.append(name)
            # 递归处理子模型
            keys.extend(gen_model_policy_keys(model[name]))

        return keys

    elif isinstance(model, Nested):
        # 处理嵌套模型
        return gen_model_policy_keys(model.model)
    else:
        return []

