"""
配置文件模块
用于管理互联网资产自动化收集系统的所有配置项

主要配置项包括：
- 数据库连接配置（MongoDB）
- 消息队列配置（RabbitMQ/Celery）
- 工具路径配置（massdns、PhantomJS等）
- 字典文件路径配置
- 端口扫描配置
- 第三方API配置（FOFA、GitHub等）
- 消息推送配置（钉钉、飞书、企业微信、邮件等）
- 域名爆破并发数配置
- 代理配置

配置文件读取顺序：
1. 默认配置（Config类中的默认值）
2. config.yaml文件覆盖（实际部署时使用）
"""
import os
import yaml
import sys

# 获取当前文件所在目录的绝对路径，作为基础路径
basedir = os.path.abspath(os.path.dirname(__file__))


def resolve_project_root():
    """
    解析项目根目录，兼容源码运行与 Docker 运行目录结构
    """
    candidates = [
        os.path.abspath(os.path.join(basedir, os.pardir, os.pardir)),  # 源码目录：<repo>/ARL/app
        os.path.abspath(os.path.join(basedir, os.pardir)),             # Docker目录：/code/app
    ]
    for candidate in candidates:
        if os.path.isdir(os.path.join(candidate, "tools")):
            return candidate
    return candidates[0]


# 项目根目录（用于定位根目录 tools 下的自定义工具和模板）
project_root = resolve_project_root()


def env_bool(name, default=False):
    """
    从环境变量读取布尔值
    """
    value = os.environ.get(name)
    if value is None:
        return default
    return str(value).strip().lower() in ["1", "true", "yes", "on"]


def env_str(name, default=""):
    """
    从环境变量读取字符串
    """
    value = os.environ.get(name)
    if value is None:
        return default
    return value


def env_int(name, default=0):
    """
    从环境变量读取整数
    """
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def safe_positive_int(value, default, min_value=1):
    """
    安全转换为正整数，非法值回退默认值
    """
    try:
        num = int(value)
    except Exception:
        return default

    if num < min_value:
        return default

    return num


class Config(object):
    """系统配置类，包含所有配置项的默认值"""
    
    # ==================== 消息队列配置 ====================
    # Celery消息队列连接地址，用于分布式任务调度
    # 格式：amqp://用户名:密码@主机:端口/虚拟主机
    CELERY_BROKER_URL = "amqp://arl:arlpassword@localhost:5672/arlv2host"
    # Gunicorn worker 数，降低默认值以减少常驻内存
    WEB_GUNICORN_WORKERS = 2
    # Celery 主任务队列并发
    CELERY_TASK_WORKER_CONCURRENCY = 2
    # Celery GitHub 队列并发
    CELERY_GITHUB_WORKER_CONCURRENCY = 1
    # Celery 预取倍率（1 表示每 worker 仅预取 1 个任务）
    CELERY_PREFETCH_MULTIPLIER = 1
    # Celery 子进程处理多少任务后重启，防止内存膨胀
    CELERY_MAX_TASKS_PER_CHILD = 20
    # Celery 子进程最大内存（KB），超过后重启，0 表示不限制
    CELERY_MAX_MEMORY_PER_CHILD = 280000

    # ==================== Redis 缓存配置 ====================
    # 默认关闭，按 config.yaml 中 REDIS.ENABLE 决定是否启用
    REDIS_ENABLE = False
    REDIS_HOST = "127.0.0.1"
    REDIS_PORT = 6379
    REDIS_DB = 0
    REDIS_PASSWORD = ""
    # Redis 缓存过期时间（秒）
    REDIS_CACHE_EXPIRE = 1800

    # ==================== 数据库配置 ====================
    # MongoDB数据库名称
    MONGO_DB = 'ARLV2'
    # MongoDB连接URL
    MONGO_URL = 'mongodb://127.0.0.1:27017/'
    # MongoDB 连接池参数（可通过环境变量 ARL_MONGO_* 覆盖）
    MONGO_MAX_POOL_SIZE = 50
    MONGO_MIN_POOL_SIZE = 0
    MONGO_MAX_IDLE_TIME_MS = 60000
    MONGO_SERVER_SELECTION_TIMEOUT_MS = 5000
    MONGO_CONNECT_TIMEOUT_MS = 5000
    MONGO_SOCKET_TIMEOUT_MS = 30000

    # ==================== 临时文件和工具路径配置 ====================
    # 临时文件存储目录
    TMP_PATH = os.path.join(basedir, 'tmp')
    # 幂等创建，避免多进程/多线程并发导入时触发 FileExistsError
    os.makedirs(TMP_PATH, exist_ok=True)
    
    # massdns工具路径，用于高速DNS查询
    MASSDNS_BIN = os.path.join(basedir, 'tools/massdns')
    # Nuclei 可执行文件路径，默认从系统 PATH 查找
    NUCLEI_BIN = "nuclei"
    # Nuclei 模板目录，优先兼容新目录布局 tools/nuclei/nuclei-templates
    NUCLEI_TEMPLATE_DIR = os.path.join(project_root, 'tools/nuclei-templates')
    _NUCLEI_TEMPLATE_DIR_ALT = os.path.join(project_root, 'tools/nuclei', 'nuclei-templates')
    if os.path.isdir(_NUCLEI_TEMPLATE_DIR_ALT):
        NUCLEI_TEMPLATE_DIR = _NUCLEI_TEMPLATE_DIR_ALT
    # 是否启用 nuclei 自动扫描（-as），在无指纹标签时用于兜底
    NUCLEI_AUTO_SCAN = True
    # 无指纹标签时使用的默认标签
    NUCLEI_DEFAULT_TAGS = "cve"
    # 指纹与 nuclei tags 的映射关系，可通过 config.yaml 覆盖
    NUCLEI_FINGER_TAG_MAP = {}
    # 是否启用内建 kscan 指纹解析
    KSCAN_FINGERPRINT_ENABLE = True
    # kscan 指纹文件路径（默认使用 ARL 内置字典）
    KSCAN_FINGERPRINT_FILE = os.path.join(basedir, 'dicts/kscan_fingerprint.json')
    # 导入前缀（空表示保留 kscan 原始名称）
    KSCAN_FINGERPRINT_NAME_PREFIX = ""
    # 正则(~=)回退策略：none / literal
    KSCAN_FINGERPRINT_REGEX_FALLBACK = "literal"
    # regex literal 最短长度
    KSCAN_FINGERPRINT_MIN_LITERAL_LEN = 5
    # 单应用最多保留规则数
    KSCAN_FINGERPRINT_MAX_RULES_PER_NAME = 30
    # 最多接收规则总数（0=不限制）
    KSCAN_FINGERPRINT_MAX_TOTAL_RULES = 12000
    # 截图引擎：playwright / phantomjs / auto
    SCREENSHOT_ENGINE = "playwright"
    # PhantomJS 可执行文件路径（legacy 兼容路径）
    PHANTOMJS_BIN = os.path.join(basedir, 'tools/phantomjs')
    # Playwright 启动超时（毫秒）
    PLAYWRIGHT_TIMEOUT_MS = 15000
    # Playwright 截图前等待（毫秒）
    PLAYWRIGHT_WAIT_MS = 1000
    # Playwright Chromium 可执行路径（为空时使用内置浏览器）
    PLAYWRIGHT_CHROMIUM_BIN = ""
    # 网页截图JS脚本路径（PhantomJS）
    SCREENSHOT_JS = os.path.join(basedir, 'tools/screenshot.js')
    # 截图文件存储目录
    SCREENSHOT_DIR = os.path.join(basedir, 'tmp_screenshot')
    # 截图失败时的默认图片
    SCREENSHOT_FAIL_IMG = os.path.join(basedir, 'dicts/noscreenshot.jpg')
    # 是否启用 worker->web 截图回传（默认开启，未配置地址时自动降级）
    SCREENSHOT_SYNC_ENABLE = True
    # web 内部截图回传接口地址（示例：http://arl-web:5003）
    SCREENSHOT_SYNC_WEB_URL = ""
    # 回传请求超时时间（秒）
    SCREENSHOT_SYNC_TIMEOUT = 10
    # 单张截图允许的最大大小（字节）
    SCREENSHOT_SYNC_MAX_SIZE = 2 * 1024 * 1024
    # 浏览器驱动JS脚本路径
    DRIVER_JS = os.path.join(basedir, 'tools/driver.js')

    # ==================== 字典文件路径配置 ====================
    # 域名爆破字典 - 测试用（小字典）
    DOMAIN_DICT_TEST = os.path.join(basedir, 'dicts/domain_dict_test.txt')
    # 域名爆破字典 - 2万条常用子域名
    DOMAIN_DICT_2W = os.path.join(basedir, 'dicts/domain_2w.txt')
    # DNS服务器列表
    DNS_SERVER = os.path.join(basedir, 'dicts/dnsserver.txt')

    # CDN信息JSON文件，用于CDN识别
    CDN_JSON_PATH = os.path.join(basedir, 'dicts/cdn_info.json')

    # WebInfoHunter 规则文件，用于Web指纹识别
    WIH_RULE_PATH = os.path.join(basedir, "dicts/wih_rules.yml")

    # 黑名单域名列表（通用）
    black_domain_path = os.path.join(basedir, 'dicts/blackdomain.txt')
    # 黑名单域名列表（和谐词汇）
    black_hexie_path = os.path.join(basedir, 'dicts/blackhexie.txt')
    # 黑名单站点列表
    black_asset_site = os.path.join(basedir, 'dicts/black_asset_site.txt')
    # altdns字典，用于域名变异生成
    altdns_dict_path = os.path.join(basedir, 'dicts/altdnsdict.txt')

    # Web应用指纹识别规则文件
    web_app_rule = os.path.join(basedir, 'dicts/webapp.json')
    # DNS查询插件目录
    dns_query_plugin_path = os.path.join(basedir, 'services/dns_query_plugin')

    # ==================== 端口扫描配置 ====================
    # TOP 1000端口列表（约1000个常用端口，用于全面端口扫描）
    TOP_1000 = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,68-70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-546,548,554-555,563,587,593,616-617,623,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1194,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1337,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666-1667,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2181,2190-2191,2196,2200,2222,2233,2251,2260,2288,2301,2323,2366,2375,2379,2381-2383,2393-2394,2399,2401,2443,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2888,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3520,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3772-3773,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3888-3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4369,4443-4446,4449,4550,4560,4567,4662,4848,4899-4900,4998,5000-5004,5006,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5111,5120,5151,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5355,5357,5387,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5601,5631-5633,5666,5672,5678-5679,5718,5722,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6080,6093,6100-6101,6106,6112,6123,6129,6156,6161,6182,6346,6379,6389,6443,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7008,7019,7025,7070,7100,7103,7106,7180,7182,7200-7201,7337,7402,7435,7443,7474,7496,7512,7625,7627,7676,7680,7687,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8016,8020-8022,8025,8030-8033,8040-8042,8045,8050,8060,8069-8070,8080-8091,8093,8099-8100,8123-8124,8161,8180-8181,8188,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8480-8481,8500,8600,8649,8651-8652,8654,8701,8744,8800,8873,8888-8889,8898-8899,8983,8989,8994,9000-9003,9009-9011,9040,9043,9050,9071,9080-9083,9090-9092,9094-9095,9099-9103,9110-9111,9200,9207,9220,9222,9290,9293,9300,9389,9391-9392,9415,9418,9443,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9987-9988,9994-10004,10009-10010,10012,10020,10024-10025,10030,10033,10050-10051,10080-10082,10101,10180,10215,10243,10250-10252,10255-10256,10566,10616-10617,10621,10626,10628-10629,10666,10778,11000-11001,11080,11110-11111,11211,11443,11967,12000,12174,12234,12265,12306,12345,12669,12750,12801-12804,12999,13456,13562,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15672,15742,16000-16001,16010,16012,16016,16018,16020,16030,16080,16113,16666,16992-16993,17877,17988,18040,18080,18089,18101,18988,19101,19283,19315,19350,19780,19801,19842,19888,19890,20000,20005-20006,20031,20221-20222,20828,20880,21000,21443,21571,22939,23502,24444,24800,25672,25734-25735,26214,27000,27017-27018,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34451,34528,34571-34573,35500,36359,37257,37310,38243,38292,38914,39297,40193,40654,40911,41084,41414,41511,42424,42510,43761,44176,44442-44443,44501,44838,45100,46675,48080,49152-49161,49163,49165-49167,49175-49176,49400,49664-49667,49670,49692,49697,49999-50003,50006,50010,50020,50070,50075,50090-50091,50095,50100,50105,50300,50389,50470,50475,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54321,54328,54345,54485,54488,55055-55056,55555,55600,56341,56737-56738,57294,57797,58080,58316,60000,60010,60020,60030,60443,61532,61616,61900,62078,63331,64623,64680,65000,65129,65389,65512,6677,8484,8360,7080,41516,8880,8881,3505,1980,8003,8004,8006,8012,7890,86,8280,8028,9060,38501,38888,28017,8053,889,9085"

    # TOP 100端口列表（约250个常用端口，用于快速扫描）
    TOP_100 = "1000,10000,10001,10030,1024,10250,10255,10256,10443,1080,1099,110,111,11211,123,12300,1234,12345,12578,13000,135,137,138,139,14000,143,1433,1434,1443,15000,15001,15002,1515,1521,16030,18001,18080,18081,1883,1988,2000,20000,20121,2049,2080,2081,2082,2083,2086,2087,20880,2096,21,2181,22,2222,22222,2323,25,2525,25672,26,27017,3000,30000,30001,30002,30003,30005,3001,30017,3002,3003,30080,3050,3306,3307,3333,3389,33890,3390,3446,3542,3689,389,4000,40001,4007,4040,443,4430,4433,444,4443,4444,445,465,4848,5000,5001,5002,5003,5005,50050,5006,50060,5007,50070,50075,50090,5050,5060,5222,5357,5432,554,5555,55555,5601,5671,5672,5673,5678,5801,587,5985,5986,6000,6060,6066,6080,6379,6380,6443,6446,6588,666,6665,6666,6699,6780,6868,7000,7001,7002,7003,7005,7010,7019,7070,7071,7080,7180,7443,7547,777,7776,7777,80,800,8000,8001,8002,8003,8005,8006,8008,8009,801,8010,8020,8025,8030,8031,8032,8060,8069,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8098,8099,81,8123,8150,8161,8162,8166,8180,8181,8191,82,8288,83,84,8443,8480,85,8686,873,8765,88,880,8800,8848,888,8880,8883,8887,8888,8889,8890,8899,8983,8989,8999,9000,9001,9002,9003,9080,9083,9090,9091,9099,9100,9109,9171,9172,9191,9200,9201,9202,9300,9301,9302,9443,9527,9529,9864,9870,9876,9944,999,9998,9999,8100"

    # TOP 10端口列表（16个最常见的Web端口，用于快速Web服务发现）
    TOP_10 = "80,443,8443,8080,8081,8888,8089,5000,5001,8085,800,81,9000,88,8001,8090"

    # ==================== FOFA API配置 ====================
    # FOFA邮箱账号
    FOFA_EMAIL = ""
    # FOFA API密钥
    FOFA_KEY = ""
    # FOFA API地址
    FOFA_URL = "https://fofa.info"

    # ==================== 系统认证配置 ====================
    # 是否开启API认证
    AUTH = False
    # API访问密钥
    API_KEY = ""
    # API 分页查询最大 size（导出接口不受此限制）
    API_PAGE_SIZE_MAX = 10000
    # 无查询条件时是否使用 estimated_document_count 作为总数统计
    API_USE_ESTIMATED_COUNT = False

    # ==================== IP黑名单配置 ====================
    # IP地址黑名单，这些IP段不会被扫描
    # 完整版本: ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "0.0.0.0/8"]
    BLACK_IPS = ["127.0.0.0/8", "0.0.0.0/8"]
    # DNS解析器列表（为空时使用系统默认解析器）
    DNS_RESOLVERS = []

    # ==================== GeoIP配置 ====================
    # GeoIP ASN数据库路径（用于IP归属查询）
    GEOIP_ASN = ""
    # GeoIP City数据库路径（用于IP地理位置查询）
    GEOIP_CITY = ""

    # ==================== 文件泄露检测字典 ====================
    # 文件泄露检测字典 - 2000条
    FILE_LEAK_TOP_2k = os.path.join(basedir, 'dicts/file_top_2000.txt')
    # 文件泄露检测字典 - 200条（快速扫描）
    FILE_LEAK_TOP_200 = os.path.join(basedir, 'dicts/file_top_200.txt')

    # ==================== 域名配置 ====================
    # 域名最大长度限制（不包括目标域名本身的长度）
    DOMAIN_MAX_LEN = 25

    # ==================== 消息推送配置 ====================
    # 钉钉机器人配置
    DINGDING_SECRET = ""  # 钉钉加签密钥
    DINGDING_ACCESS_TOKEN = ""  # 钉钉访问令牌

    # 钉钉开放平台（知识库）配置
    DINGTALK_KB_ENABLE = False
    DINGTALK_API_BASE_URL = "https://api.dingtalk.com"
    DINGTALK_CORP_ID = ""
    DINGTALK_APP_KEY = ""
    DINGTALK_APP_SECRET = ""
    DINGTALK_OPERATOR_ID = ""
    DINGTALK_WORKSPACE_ID = ""
    DINGTALK_PARENT_NODE_ID = ""
    DINGTALK_KB_CREATE_NODE_PATH = "/v1.0/doc/workspaces/{workspace_id}/docs"
    DINGTALK_KB_TIMEOUT = 20
    DINGTALK_KB_TITLE_PREFIX = "互联网资产自动化收集"
    DINGTALK_KB_DRY_RUN = False
    DINGTALK_REPORT_BASE_URL = ""
    DINGTALK_SSL_CERT_NOTIFY_ENABLE = False

    # 飞书机器人配置
    FEISHU_WEBHOOK = ""  # 飞书Webhook地址
    FEISHU_SECRET = ""  # 飞书加签密钥

    # 企业微信机器人配置
    WX_WORK_WEBHOOK = ""  # 企业微信Webhook地址

    # 邮件推送配置
    EMAIL_HOST = ""  # 邮件服务器地址
    EMAIL_PORT = ""  # 邮件服务器端口
    EMAIL_USERNAME = ""  # 邮箱用户名
    EMAIL_PASSWORD = ""  # 邮箱密码
    EMAIL_TO = ""  # 接收邮箱地址

    # ==================== 域名限制配置 ====================
    # 禁止扫描的域名列表（敏感域名）
    # 默认可配置为: ["gov.cn", "edu.cn", "org.cn"]
    FORBIDDEN_DOMAINS = []

    # ==================== GitHub配置 ====================
    # GitHub Personal Access Token（用于GitHub代码泄露检测）
    GITHUB_TOKEN = ""
    # GitHub Hash缓存文件路径
    GITHUB_HASH_FILE = os.path.join(TMP_PATH, 'github.hash')

    # ==================== 并发控制配置 ====================
    # 域名爆破并发数（普通域名字典爆破）
    DOMAIN_BRUTE_CONCURRENT = 180
    # 组合生成的域名爆破并发数（altdns变异域名爆破）
    ALT_DNS_CONCURRENT = 800
    # 域名解析并发
    DOMAIN_RESOLVE_CONCURRENCY = 10
    # 域名信息构建并发
    DOMAIN_INFO_CONCURRENCY = 10
    # HTTP可用性检查并发
    HTTP_CHECK_CONCURRENCY = 10
    # 站点抓取并发
    HTTP_FETCH_SITE_CONCURRENCY = 8
    # 站点探测并发
    PROBE_HTTP_CONCURRENCY = 8
    # 截图并发
    SITE_SCREENSHOT_CONCURRENCY = 4
    # NPoC 服务识别并发
    NPOC_SNIFFER_CONCURRENCY = 8
    # NPoC POC 扫描并发
    NPOC_POC_CONCURRENCY = 6
    # NPoC 弱口令并发
    NPOC_BRUTE_CONCURRENCY = 4
    # 资产站点监控并发
    ASSET_SITE_MONITOR_CONCURRENCY = 8
    # 资产站点发现并发
    ASSET_SITE_DISCOVERY_CONCURRENCY = 10

    # ==================== 代理配置 ====================
    # HTTP代理地址（用于需要代理的网络请求）
    PROXY_URL = ""

    # ==================== 插件配置 ====================
    # DNS查询插件配置字典
    QUERY_PLUGIN_CONFIG = dict()
    # 是否启用“域名A记录IP -> 三方API反查域名”增强链路
    IP_PIVOT_QUERY_ENABLE = True
    # 单任务最多参与IP反查的IP数量（防止配额和时延失控）
    IP_PIVOT_QUERY_MAX_IPS = 20
    # 单任务最多接收IP反查新增域名数量
    IP_PIVOT_QUERY_MAX_DOMAINS = 200
    # IP反查命中域名是否必须限制在当前任务主域范围内
    IP_PIVOT_QUERY_REQUIRE_SCOPE = True
    # IP反查前是否跳过已识别为CDN/WAF的IP
    IP_PIVOT_QUERY_SKIP_CDN = True
    # 是否启用“证书 -> 三方API反查域名”增强链路
    CERT_PIVOT_QUERY_ENABLE = True
    # 单任务最多参与证书反查的证书数量
    CERT_PIVOT_QUERY_MAX_CERTS = 20
    # 单任务最多接收证书反查新增域名数量
    CERT_PIVOT_QUERY_MAX_DOMAINS = 200
    # 证书反查命中域名是否必须限制在当前任务主域范围内
    CERT_PIVOT_QUERY_REQUIRE_SCOPE = True
    # 证书反查前是否跳过已识别为CDN/WAF的证书来源IP
    CERT_PIVOT_QUERY_SKIP_CDN = True

    # ==================== WebHook配置 ====================
    # 自定义WebHook推送地址
    WEB_HOOK_URL = ""
    # WebHook验证Token
    WEB_HOOK_TOKEN = ""


# ==================== 从config.yaml加载配置 ====================
# 读取外部YAML配置文件，覆盖默认配置
try:
    with open(os.path.join(basedir, 'config.yaml')) as f:
        y = yaml.load(f, Loader=yaml.SafeLoader)

    # --- MongoDB配置 ---
    Config.MONGO_URL = y["MONGO"]["URI"]
    Config.MONGO_DB = y["MONGO"]["DB"]

    # --- Celery配置 ---
    Config.CELERY_BROKER_URL = y["CELERY"]["BROKER_URL"]
    web_gunicorn_workers = y["ARL"].get("WEB_GUNICORN_WORKERS")
    if web_gunicorn_workers is not None:
        Config.WEB_GUNICORN_WORKERS = safe_positive_int(
            web_gunicorn_workers, Config.WEB_GUNICORN_WORKERS
        )

    celery_task_worker_concurrency = y["ARL"].get("CELERY_TASK_WORKER_CONCURRENCY")
    if celery_task_worker_concurrency is not None:
        Config.CELERY_TASK_WORKER_CONCURRENCY = safe_positive_int(
            celery_task_worker_concurrency, Config.CELERY_TASK_WORKER_CONCURRENCY
        )

    celery_github_worker_concurrency = y["ARL"].get("CELERY_GITHUB_WORKER_CONCURRENCY")
    if celery_github_worker_concurrency is not None:
        Config.CELERY_GITHUB_WORKER_CONCURRENCY = safe_positive_int(
            celery_github_worker_concurrency, Config.CELERY_GITHUB_WORKER_CONCURRENCY
        )

    celery_prefetch_multiplier = y["ARL"].get("CELERY_PREFETCH_MULTIPLIER")
    if celery_prefetch_multiplier is not None:
        Config.CELERY_PREFETCH_MULTIPLIER = safe_positive_int(
            celery_prefetch_multiplier, Config.CELERY_PREFETCH_MULTIPLIER
        )

    celery_max_tasks_per_child = y["ARL"].get("CELERY_MAX_TASKS_PER_CHILD")
    if celery_max_tasks_per_child is not None:
        Config.CELERY_MAX_TASKS_PER_CHILD = safe_positive_int(
            celery_max_tasks_per_child, Config.CELERY_MAX_TASKS_PER_CHILD
        )

    celery_max_memory_per_child = y["ARL"].get("CELERY_MAX_MEMORY_PER_CHILD")
    if celery_max_memory_per_child is not None:
        Config.CELERY_MAX_MEMORY_PER_CHILD = safe_positive_int(
            celery_max_memory_per_child, Config.CELERY_MAX_MEMORY_PER_CHILD
        )

    # --- Redis配置 ---
    if y.get("REDIS"):
        Config.REDIS_ENABLE = bool(y["REDIS"].get("ENABLE", False))
        Config.REDIS_HOST = y["REDIS"].get("HOST", Config.REDIS_HOST)
        Config.REDIS_PORT = int(y["REDIS"].get("PORT", Config.REDIS_PORT))
        Config.REDIS_DB = int(y["REDIS"].get("DB", Config.REDIS_DB))
        Config.REDIS_PASSWORD = y["REDIS"].get("PASSWORD", Config.REDIS_PASSWORD)
        Config.REDIS_CACHE_EXPIRE = int(y["REDIS"].get("CACHE_EXPIRE", Config.REDIS_CACHE_EXPIRE))

    # --- FOFA配置 ---
    Config.FOFA_EMAIL = y["FOFA"]["EMAIL"]
    Config.FOFA_KEY = y["FOFA"]["KEY"]
    if y["FOFA"].get("URL"):
        Config.FOFA_URL = y["FOFA"]["URL"]

    # --- GeoIP配置 ---
    Config.GEOIP_CITY = y["GEOIP"]["CITY"]
    Config.GEOIP_ASN = y["GEOIP"]["ASN"]

    # --- 系统认证配置 ---
    Config.AUTH = y["ARL"]["AUTH"]
    Config.API_KEY = y["ARL"]["API_KEY"]
    Config.BLACK_IPS = y["ARL"]["BLACK_IPS"]
    dns_resolvers = y["ARL"].get("DNS_RESOLVERS")
    if dns_resolvers is not None:
        if not isinstance(dns_resolvers, list):
            print("arl.dns_resolvers is not list")
            sys.exit(-1)

        config_dns_resolvers = []
        for resolver in dns_resolvers:
            if not resolver:
                continue

            if not isinstance(resolver, str):
                print("arl.dns_resolvers item is not string")
                sys.exit(-1)

            resolver = resolver.strip()
            if resolver:
                config_dns_resolvers.append(resolver)

        Config.DNS_RESOLVERS = config_dns_resolvers

    # --- TOP 10端口自定义配置 ---
    if y["ARL"].get("PORT_TOP_10"):
        Config.TOP_10 = y["ARL"]["PORT_TOP_10"]

    # --- PhantomJS 路径配置 ---
    if y["ARL"].get("PHANTOMJS_BIN"):
        Config.PHANTOMJS_BIN = y["ARL"]["PHANTOMJS_BIN"]
    if y["ARL"].get("SCREENSHOT_ENGINE"):
        Config.SCREENSHOT_ENGINE = str(y["ARL"]["SCREENSHOT_ENGINE"]).strip().lower()
    if y["ARL"].get("PLAYWRIGHT_TIMEOUT_MS") is not None:
        Config.PLAYWRIGHT_TIMEOUT_MS = safe_positive_int(
            int(y["ARL"]["PLAYWRIGHT_TIMEOUT_MS"]), Config.PLAYWRIGHT_TIMEOUT_MS
        )
    if y["ARL"].get("PLAYWRIGHT_WAIT_MS") is not None:
        Config.PLAYWRIGHT_WAIT_MS = safe_positive_int(
            int(y["ARL"]["PLAYWRIGHT_WAIT_MS"]), Config.PLAYWRIGHT_WAIT_MS
        )
    if y["ARL"].get("PLAYWRIGHT_CHROMIUM_BIN"):
        Config.PLAYWRIGHT_CHROMIUM_BIN = str(y["ARL"]["PLAYWRIGHT_CHROMIUM_BIN"]).strip()

    # --- 截图回传配置 ---
    if y["ARL"].get("SCREENSHOT_SYNC_ENABLE") is not None:
        Config.SCREENSHOT_SYNC_ENABLE = bool(y["ARL"]["SCREENSHOT_SYNC_ENABLE"])

    if y["ARL"].get("SCREENSHOT_SYNC_WEB_URL"):
        Config.SCREENSHOT_SYNC_WEB_URL = y["ARL"]["SCREENSHOT_SYNC_WEB_URL"]

    if y["ARL"].get("SCREENSHOT_SYNC_TIMEOUT"):
        Config.SCREENSHOT_SYNC_TIMEOUT = int(y["ARL"]["SCREENSHOT_SYNC_TIMEOUT"])

    if y["ARL"].get("SCREENSHOT_SYNC_MAX_SIZE"):
        Config.SCREENSHOT_SYNC_MAX_SIZE = int(y["ARL"]["SCREENSHOT_SYNC_MAX_SIZE"])

    # --- Nuclei 相关配置 ---
    if y["ARL"].get("NUCLEI_BIN"):
        Config.NUCLEI_BIN = y["ARL"]["NUCLEI_BIN"]

    if y["ARL"].get("NUCLEI_TEMPLATE_DIR") is not None:
        Config.NUCLEI_TEMPLATE_DIR = y["ARL"]["NUCLEI_TEMPLATE_DIR"]

    if y["ARL"].get("NUCLEI_AUTO_SCAN") is not None:
        Config.NUCLEI_AUTO_SCAN = bool(y["ARL"]["NUCLEI_AUTO_SCAN"])

    if y["ARL"].get("NUCLEI_DEFAULT_TAGS"):
        Config.NUCLEI_DEFAULT_TAGS = y["ARL"]["NUCLEI_DEFAULT_TAGS"]

    nuclei_finger_tag_map = y["ARL"].get("NUCLEI_FINGER_TAG_MAP")
    if isinstance(nuclei_finger_tag_map, dict):
        Config.NUCLEI_FINGER_TAG_MAP = nuclei_finger_tag_map

    if y["ARL"].get("KSCAN_FINGERPRINT_ENABLE") is not None:
        Config.KSCAN_FINGERPRINT_ENABLE = bool(y["ARL"]["KSCAN_FINGERPRINT_ENABLE"])

    if y["ARL"].get("KSCAN_FINGERPRINT_FILE"):
        Config.KSCAN_FINGERPRINT_FILE = y["ARL"]["KSCAN_FINGERPRINT_FILE"]

    if y["ARL"].get("KSCAN_FINGERPRINT_NAME_PREFIX") is not None:
        Config.KSCAN_FINGERPRINT_NAME_PREFIX = str(y["ARL"]["KSCAN_FINGERPRINT_NAME_PREFIX"])

    if y["ARL"].get("KSCAN_FINGERPRINT_REGEX_FALLBACK"):
        Config.KSCAN_FINGERPRINT_REGEX_FALLBACK = y["ARL"]["KSCAN_FINGERPRINT_REGEX_FALLBACK"]

    if y["ARL"].get("KSCAN_FINGERPRINT_MIN_LITERAL_LEN") is not None:
        Config.KSCAN_FINGERPRINT_MIN_LITERAL_LEN = int(y["ARL"]["KSCAN_FINGERPRINT_MIN_LITERAL_LEN"])

    if y["ARL"].get("KSCAN_FINGERPRINT_MAX_RULES_PER_NAME") is not None:
        Config.KSCAN_FINGERPRINT_MAX_RULES_PER_NAME = int(y["ARL"]["KSCAN_FINGERPRINT_MAX_RULES_PER_NAME"])

    if y["ARL"].get("KSCAN_FINGERPRINT_MAX_TOTAL_RULES") is not None:
        Config.KSCAN_FINGERPRINT_MAX_TOTAL_RULES = int(y["ARL"]["KSCAN_FINGERPRINT_MAX_TOTAL_RULES"])

    # --- 公网A记录IP三方反查增强配置 ---
    if y["ARL"].get("IP_PIVOT_QUERY_ENABLE") is not None:
        Config.IP_PIVOT_QUERY_ENABLE = bool(y["ARL"]["IP_PIVOT_QUERY_ENABLE"])

    if y["ARL"].get("IP_PIVOT_QUERY_MAX_IPS") is not None:
        Config.IP_PIVOT_QUERY_MAX_IPS = int(y["ARL"]["IP_PIVOT_QUERY_MAX_IPS"])

    if y["ARL"].get("IP_PIVOT_QUERY_MAX_DOMAINS") is not None:
        Config.IP_PIVOT_QUERY_MAX_DOMAINS = int(y["ARL"]["IP_PIVOT_QUERY_MAX_DOMAINS"])

    if y["ARL"].get("IP_PIVOT_QUERY_REQUIRE_SCOPE") is not None:
        Config.IP_PIVOT_QUERY_REQUIRE_SCOPE = bool(y["ARL"]["IP_PIVOT_QUERY_REQUIRE_SCOPE"])

    if y["ARL"].get("IP_PIVOT_QUERY_SKIP_CDN") is not None:
        Config.IP_PIVOT_QUERY_SKIP_CDN = bool(y["ARL"]["IP_PIVOT_QUERY_SKIP_CDN"])

    if y["ARL"].get("CERT_PIVOT_QUERY_ENABLE") is not None:
        Config.CERT_PIVOT_QUERY_ENABLE = bool(y["ARL"]["CERT_PIVOT_QUERY_ENABLE"])

    if y["ARL"].get("CERT_PIVOT_QUERY_MAX_CERTS") is not None:
        Config.CERT_PIVOT_QUERY_MAX_CERTS = int(y["ARL"]["CERT_PIVOT_QUERY_MAX_CERTS"])

    if y["ARL"].get("CERT_PIVOT_QUERY_MAX_DOMAINS") is not None:
        Config.CERT_PIVOT_QUERY_MAX_DOMAINS = int(y["ARL"]["CERT_PIVOT_QUERY_MAX_DOMAINS"])

    if y["ARL"].get("CERT_PIVOT_QUERY_REQUIRE_SCOPE") is not None:
        Config.CERT_PIVOT_QUERY_REQUIRE_SCOPE = bool(y["ARL"]["CERT_PIVOT_QUERY_REQUIRE_SCOPE"])

    if y["ARL"].get("CERT_PIVOT_QUERY_SKIP_CDN") is not None:
        Config.CERT_PIVOT_QUERY_SKIP_CDN = bool(y["ARL"]["CERT_PIVOT_QUERY_SKIP_CDN"])


    # --- 文件泄露字典自定义配置 ---
    if y["ARL"].get("FILE_LEAK_DICT"):
        file_leak_dict = y["ARL"]["FILE_LEAK_DICT"]
        if os.path.isfile(file_leak_dict):
            Config.FILE_LEAK_TOP_2k = file_leak_dict
        else:
            print("Warning {} is not file".format(file_leak_dict))

    # --- 域名爆破字典自定义配置 ---
    if y["ARL"].get("DOMAIN_DICT"):
        domain_dict = y["ARL"]["DOMAIN_DICT"]
        if os.path.isfile(domain_dict):
            Config.DOMAIN_DICT_2W = domain_dict
        else:
            print("Warning {} is not file".format(domain_dict))

    # --- 禁止扫描域名配置 ---
    forbidden_domains = y["ARL"].get("FORBIDDEN_DOMAINS")
    if forbidden_domains is None:
        pass  # 使用默认配置
    else:
        Config.FORBIDDEN_DOMAINS = []
        if not isinstance(forbidden_domains, list):
            print("arl.forbidden_domains is not list")
            sys.exit(-1)
        elif forbidden_domains:
            Config.FORBIDDEN_DOMAINS = forbidden_domains

    # --- 钉钉机器人配置 ---
    if y.get("DINGDING"):
        if y["DINGDING"].get("SECRET"):
            Config.DINGDING_SECRET = y["DINGDING"]["SECRET"]

        if y["DINGDING"].get("ACCESS_TOKEN"):
            Config.DINGDING_ACCESS_TOKEN = y["DINGDING"]["ACCESS_TOKEN"]

    # --- 钉钉开放平台（知识库）配置 ---
    if y.get("DINGTALK_API"):
        dingtalk_api_conf = y["DINGTALK_API"]
        if dingtalk_api_conf.get("ENABLE") is not None:
            Config.DINGTALK_KB_ENABLE = bool(dingtalk_api_conf["ENABLE"])
        if dingtalk_api_conf.get("BASE_URL"):
            Config.DINGTALK_API_BASE_URL = dingtalk_api_conf["BASE_URL"]
        if dingtalk_api_conf.get("CORP_ID"):
            Config.DINGTALK_CORP_ID = dingtalk_api_conf["CORP_ID"]
        if dingtalk_api_conf.get("APP_KEY"):
            Config.DINGTALK_APP_KEY = dingtalk_api_conf["APP_KEY"]
        if dingtalk_api_conf.get("APP_SECRET"):
            Config.DINGTALK_APP_SECRET = dingtalk_api_conf["APP_SECRET"]
        if dingtalk_api_conf.get("OPERATOR_ID"):
            Config.DINGTALK_OPERATOR_ID = dingtalk_api_conf["OPERATOR_ID"]
        if dingtalk_api_conf.get("WORKSPACE_ID"):
            Config.DINGTALK_WORKSPACE_ID = dingtalk_api_conf["WORKSPACE_ID"]
        if dingtalk_api_conf.get("PARENT_NODE_ID"):
            Config.DINGTALK_PARENT_NODE_ID = dingtalk_api_conf["PARENT_NODE_ID"]
        if dingtalk_api_conf.get("CREATE_NODE_PATH"):
            Config.DINGTALK_KB_CREATE_NODE_PATH = dingtalk_api_conf["CREATE_NODE_PATH"]
        if dingtalk_api_conf.get("KB_TIMEOUT"):
            Config.DINGTALK_KB_TIMEOUT = int(dingtalk_api_conf["KB_TIMEOUT"])
        if dingtalk_api_conf.get("TITLE_PREFIX"):
            Config.DINGTALK_KB_TITLE_PREFIX = dingtalk_api_conf["TITLE_PREFIX"]
        if dingtalk_api_conf.get("DRY_RUN") is not None:
            Config.DINGTALK_KB_DRY_RUN = bool(dingtalk_api_conf["DRY_RUN"])
        if dingtalk_api_conf.get("REPORT_BASE_URL"):
            Config.DINGTALK_REPORT_BASE_URL = dingtalk_api_conf["REPORT_BASE_URL"]
        if dingtalk_api_conf.get("SSL_CERT_NOTIFY_ENABLE") is not None:
            Config.DINGTALK_SSL_CERT_NOTIFY_ENABLE = bool(dingtalk_api_conf["SSL_CERT_NOTIFY_ENABLE"])

    # --- 邮件推送配置 ---
    if y.get("EMAIL"):
        if y["EMAIL"].get("HOST"):
            Config.EMAIL_HOST = y["EMAIL"]["HOST"]

        if y["EMAIL"].get("PORT"):
            Config.EMAIL_PORT = int(y["EMAIL"]["PORT"])

        if y["EMAIL"].get("USERNAME"):
            Config.EMAIL_USERNAME = y["EMAIL"]["USERNAME"]

        if y["EMAIL"].get("PASSWORD"):
            Config.EMAIL_PASSWORD = y["EMAIL"]["PASSWORD"]

        if y["EMAIL"].get("TO"):
            Config.EMAIL_TO = y["EMAIL"]["TO"]

    # --- GitHub Token配置 ---
    if y.get("GITHUB"):
        if y["GITHUB"].get("TOKEN"):
            Config.GITHUB_TOKEN = y["GITHUB"]["TOKEN"]

    # --- 并发与资源配置（声明式批量加载） ---
    _ARL_POSITIVE_INT_KEYS = [
        "DOMAIN_BRUTE_CONCURRENT",
        "ALT_DNS_CONCURRENT",
        "DOMAIN_RESOLVE_CONCURRENCY",
        "DOMAIN_INFO_CONCURRENCY",
        "HTTP_CHECK_CONCURRENCY",
        "HTTP_FETCH_SITE_CONCURRENCY",
        "PROBE_HTTP_CONCURRENCY",
        "SITE_SCREENSHOT_CONCURRENCY",
        "NPOC_SNIFFER_CONCURRENCY",
        "NPOC_POC_CONCURRENCY",
        "NPOC_BRUTE_CONCURRENCY",
        "ASSET_SITE_MONITOR_CONCURRENCY",
        "ASSET_SITE_DISCOVERY_CONCURRENCY",
    ]
    for _key in _ARL_POSITIVE_INT_KEYS:
        _val = y["ARL"].get(_key)
        if _val is not None:
            setattr(Config, _key, safe_positive_int(_val, getattr(Config, _key)))

    # --- 代理配置 ---
    if y.get("PROXY"):
        if y["PROXY"].get("HTTP_URL"):
            Config.PROXY_URL = y["PROXY"]["HTTP_URL"]

    # --- 域名查询插件配置 ---
    if y.get("QUERY_PLUGIN"):
        query_plugin_conf = y["QUERY_PLUGIN"]
        if isinstance(query_plugin_conf, dict):
            Config.QUERY_PLUGIN_CONFIG = query_plugin_conf

    # --- WebHook配置 ---
    if y.get("WEBHOOK"):
        if y["WEBHOOK"].get("URL"):
            Config.WEB_HOOK_URL = y["WEBHOOK"]["URL"]
        if y["WEBHOOK"].get("TOKEN"):
            Config.WEB_HOOK_TOKEN = y["WEBHOOK"]["TOKEN"]

    # --- 飞书机器人配置 ---
    if y.get("FEISHU"):
        if y["FEISHU"].get("WEBHOOK_URL"):
            Config.FEISHU_WEBHOOK = y["FEISHU"]["WEBHOOK_URL"]
        if y["FEISHU"].get("SECRET"):
            Config.FEISHU_SECRET = y["FEISHU"]["SECRET"]

    # --- 企业微信机器人配置 ---
    if y.get("WXWORK"):
        if y["WXWORK"].get("WEBHOOK_URL"):
            Config.WX_WORK_WEBHOOK = y["WXWORK"]["WEBHOOK_URL"]

    # --- 环境变量覆盖（便于 K8s Secret/ConfigMap 注入） ---
    Config.DINGTALK_KB_ENABLE = env_bool("ARL_DINGTALK_KB_ENABLE", Config.DINGTALK_KB_ENABLE)
    Config.DINGTALK_API_BASE_URL = env_str("ARL_DINGTALK_API_BASE_URL", Config.DINGTALK_API_BASE_URL)
    Config.DINGTALK_CORP_ID = env_str("ARL_DINGTALK_CORP_ID", Config.DINGTALK_CORP_ID)
    Config.DINGTALK_APP_KEY = env_str("ARL_DINGTALK_APP_KEY", Config.DINGTALK_APP_KEY)
    Config.DINGTALK_APP_SECRET = env_str("ARL_DINGTALK_APP_SECRET", Config.DINGTALK_APP_SECRET)
    Config.DINGTALK_OPERATOR_ID = env_str("ARL_DINGTALK_OPERATOR_ID", Config.DINGTALK_OPERATOR_ID)
    Config.DINGTALK_WORKSPACE_ID = env_str("ARL_DINGTALK_WORKSPACE_ID", Config.DINGTALK_WORKSPACE_ID)
    Config.DINGTALK_PARENT_NODE_ID = env_str("ARL_DINGTALK_PARENT_NODE_ID", Config.DINGTALK_PARENT_NODE_ID)
    Config.DINGTALK_KB_CREATE_NODE_PATH = env_str("ARL_DINGTALK_KB_CREATE_NODE_PATH", Config.DINGTALK_KB_CREATE_NODE_PATH)
    Config.DINGTALK_KB_TIMEOUT = env_int("ARL_DINGTALK_KB_TIMEOUT", Config.DINGTALK_KB_TIMEOUT)
    Config.DINGTALK_KB_TITLE_PREFIX = env_str("ARL_DINGTALK_KB_TITLE_PREFIX", Config.DINGTALK_KB_TITLE_PREFIX)
    Config.DINGTALK_KB_DRY_RUN = env_bool("ARL_DINGTALK_KB_DRY_RUN", Config.DINGTALK_KB_DRY_RUN)
    Config.DINGTALK_REPORT_BASE_URL = env_str("ARL_DINGTALK_REPORT_BASE_URL", Config.DINGTALK_REPORT_BASE_URL)
    Config.DINGTALK_SSL_CERT_NOTIFY_ENABLE = env_bool(
        "ARL_DINGTALK_SSL_CERT_NOTIFY_ENABLE", Config.DINGTALK_SSL_CERT_NOTIFY_ENABLE
    )
    Config.PHANTOMJS_BIN = env_str("ARL_PHANTOMJS_BIN", Config.PHANTOMJS_BIN)
    Config.SCREENSHOT_ENGINE = env_str("ARL_SCREENSHOT_ENGINE", Config.SCREENSHOT_ENGINE).strip().lower()
    Config.PLAYWRIGHT_TIMEOUT_MS = safe_positive_int(
        env_int("ARL_PLAYWRIGHT_TIMEOUT_MS", Config.PLAYWRIGHT_TIMEOUT_MS),
        Config.PLAYWRIGHT_TIMEOUT_MS
    )
    Config.PLAYWRIGHT_WAIT_MS = safe_positive_int(
        env_int("ARL_PLAYWRIGHT_WAIT_MS", Config.PLAYWRIGHT_WAIT_MS),
        Config.PLAYWRIGHT_WAIT_MS
    )
    Config.PLAYWRIGHT_CHROMIUM_BIN = env_str(
        "ARL_PLAYWRIGHT_CHROMIUM_BIN", Config.PLAYWRIGHT_CHROMIUM_BIN
    ).strip()
    if Config.SCREENSHOT_ENGINE not in ["playwright", "phantomjs", "auto"]:
        Config.SCREENSHOT_ENGINE = "playwright"
    Config.SCREENSHOT_SYNC_ENABLE = env_bool("ARL_SCREENSHOT_SYNC_ENABLE", Config.SCREENSHOT_SYNC_ENABLE)
    Config.SCREENSHOT_SYNC_WEB_URL = env_str("ARL_SCREENSHOT_SYNC_WEB_URL", Config.SCREENSHOT_SYNC_WEB_URL)
    Config.SCREENSHOT_SYNC_TIMEOUT = env_int("ARL_SCREENSHOT_SYNC_TIMEOUT", Config.SCREENSHOT_SYNC_TIMEOUT)
    Config.SCREENSHOT_SYNC_MAX_SIZE = env_int("ARL_SCREENSHOT_SYNC_MAX_SIZE", Config.SCREENSHOT_SYNC_MAX_SIZE)
    Config.NUCLEI_BIN = env_str("ARL_NUCLEI_BIN", Config.NUCLEI_BIN)
    Config.NUCLEI_TEMPLATE_DIR = env_str("ARL_NUCLEI_TEMPLATE_DIR", Config.NUCLEI_TEMPLATE_DIR)
    Config.NUCLEI_AUTO_SCAN = env_bool("ARL_NUCLEI_AUTO_SCAN", Config.NUCLEI_AUTO_SCAN)
    Config.NUCLEI_DEFAULT_TAGS = env_str("ARL_NUCLEI_DEFAULT_TAGS", Config.NUCLEI_DEFAULT_TAGS)
    Config.KSCAN_FINGERPRINT_ENABLE = env_bool(
        "ARL_KSCAN_FINGERPRINT_ENABLE", Config.KSCAN_FINGERPRINT_ENABLE
    )
    Config.KSCAN_FINGERPRINT_FILE = env_str(
        "ARL_KSCAN_FINGERPRINT_FILE", Config.KSCAN_FINGERPRINT_FILE
    )
    Config.KSCAN_FINGERPRINT_NAME_PREFIX = env_str(
        "ARL_KSCAN_FINGERPRINT_NAME_PREFIX", Config.KSCAN_FINGERPRINT_NAME_PREFIX
    )
    Config.KSCAN_FINGERPRINT_REGEX_FALLBACK = env_str(
        "ARL_KSCAN_FINGERPRINT_REGEX_FALLBACK", Config.KSCAN_FINGERPRINT_REGEX_FALLBACK
    )
    Config.KSCAN_FINGERPRINT_MIN_LITERAL_LEN = env_int(
        "ARL_KSCAN_FINGERPRINT_MIN_LITERAL_LEN", Config.KSCAN_FINGERPRINT_MIN_LITERAL_LEN
    )
    Config.KSCAN_FINGERPRINT_MAX_RULES_PER_NAME = env_int(
        "ARL_KSCAN_FINGERPRINT_MAX_RULES_PER_NAME", Config.KSCAN_FINGERPRINT_MAX_RULES_PER_NAME
    )
    Config.KSCAN_FINGERPRINT_MAX_TOTAL_RULES = env_int(
        "ARL_KSCAN_FINGERPRINT_MAX_TOTAL_RULES", Config.KSCAN_FINGERPRINT_MAX_TOTAL_RULES
    )
    Config.IP_PIVOT_QUERY_ENABLE = env_bool("ARL_IP_PIVOT_QUERY_ENABLE", Config.IP_PIVOT_QUERY_ENABLE)
    Config.IP_PIVOT_QUERY_MAX_IPS = env_int("ARL_IP_PIVOT_QUERY_MAX_IPS", Config.IP_PIVOT_QUERY_MAX_IPS)
    Config.IP_PIVOT_QUERY_MAX_DOMAINS = env_int("ARL_IP_PIVOT_QUERY_MAX_DOMAINS", Config.IP_PIVOT_QUERY_MAX_DOMAINS)
    Config.IP_PIVOT_QUERY_REQUIRE_SCOPE = env_bool(
        "ARL_IP_PIVOT_QUERY_REQUIRE_SCOPE", Config.IP_PIVOT_QUERY_REQUIRE_SCOPE
    )
    Config.IP_PIVOT_QUERY_SKIP_CDN = env_bool("ARL_IP_PIVOT_QUERY_SKIP_CDN", Config.IP_PIVOT_QUERY_SKIP_CDN)
    Config.CERT_PIVOT_QUERY_ENABLE = env_bool("ARL_CERT_PIVOT_QUERY_ENABLE", Config.CERT_PIVOT_QUERY_ENABLE)
    Config.CERT_PIVOT_QUERY_MAX_CERTS = env_int("ARL_CERT_PIVOT_QUERY_MAX_CERTS", Config.CERT_PIVOT_QUERY_MAX_CERTS)
    Config.CERT_PIVOT_QUERY_MAX_DOMAINS = env_int(
        "ARL_CERT_PIVOT_QUERY_MAX_DOMAINS", Config.CERT_PIVOT_QUERY_MAX_DOMAINS
    )
    Config.CERT_PIVOT_QUERY_REQUIRE_SCOPE = env_bool(
        "ARL_CERT_PIVOT_QUERY_REQUIRE_SCOPE", Config.CERT_PIVOT_QUERY_REQUIRE_SCOPE
    )
    Config.CERT_PIVOT_QUERY_SKIP_CDN = env_bool("ARL_CERT_PIVOT_QUERY_SKIP_CDN", Config.CERT_PIVOT_QUERY_SKIP_CDN)
    Config.WEB_GUNICORN_WORKERS = safe_positive_int(
        env_int("ARL_WEB_GUNICORN_WORKERS", Config.WEB_GUNICORN_WORKERS),
        Config.WEB_GUNICORN_WORKERS
    )
    Config.CELERY_TASK_WORKER_CONCURRENCY = safe_positive_int(
        env_int("ARL_CELERY_TASK_WORKER_CONCURRENCY", Config.CELERY_TASK_WORKER_CONCURRENCY),
        Config.CELERY_TASK_WORKER_CONCURRENCY
    )
    Config.CELERY_GITHUB_WORKER_CONCURRENCY = safe_positive_int(
        env_int("ARL_CELERY_GITHUB_WORKER_CONCURRENCY", Config.CELERY_GITHUB_WORKER_CONCURRENCY),
        Config.CELERY_GITHUB_WORKER_CONCURRENCY
    )
    Config.CELERY_PREFETCH_MULTIPLIER = safe_positive_int(
        env_int("ARL_CELERY_PREFETCH_MULTIPLIER", Config.CELERY_PREFETCH_MULTIPLIER),
        Config.CELERY_PREFETCH_MULTIPLIER
    )
    Config.CELERY_MAX_TASKS_PER_CHILD = safe_positive_int(
        env_int("ARL_CELERY_MAX_TASKS_PER_CHILD", Config.CELERY_MAX_TASKS_PER_CHILD),
        Config.CELERY_MAX_TASKS_PER_CHILD
    )
    Config.CELERY_MAX_MEMORY_PER_CHILD = safe_positive_int(
        env_int("ARL_CELERY_MAX_MEMORY_PER_CHILD", Config.CELERY_MAX_MEMORY_PER_CHILD),
        Config.CELERY_MAX_MEMORY_PER_CHILD
    )
    # --- 环境变量覆盖：并发数配置（声明式） ---
    for _key in _ARL_POSITIVE_INT_KEYS:
        _env_name = "ARL_{}".format(_key)
        setattr(Config, _key, safe_positive_int(
            env_int(_env_name, getattr(Config, _key)),
            getattr(Config, _key)
        ))

    # --- 环境变量覆盖：MongoDB 连接池参数 ---
    Config.MONGO_MAX_POOL_SIZE = safe_positive_int(
        env_int("ARL_MONGO_MAX_POOL_SIZE", Config.MONGO_MAX_POOL_SIZE),
        Config.MONGO_MAX_POOL_SIZE
    )
    Config.MONGO_MIN_POOL_SIZE = env_int("ARL_MONGO_MIN_POOL_SIZE", Config.MONGO_MIN_POOL_SIZE)
    if Config.MONGO_MIN_POOL_SIZE < 0:
        Config.MONGO_MIN_POOL_SIZE = 0
    if Config.MONGO_MIN_POOL_SIZE > Config.MONGO_MAX_POOL_SIZE:
        Config.MONGO_MIN_POOL_SIZE = Config.MONGO_MAX_POOL_SIZE
    Config.MONGO_MAX_IDLE_TIME_MS = safe_positive_int(
        env_int("ARL_MONGO_MAX_IDLE_TIME_MS", Config.MONGO_MAX_IDLE_TIME_MS),
        Config.MONGO_MAX_IDLE_TIME_MS
    )
    Config.MONGO_SERVER_SELECTION_TIMEOUT_MS = safe_positive_int(
        env_int("ARL_MONGO_SERVER_SELECTION_TIMEOUT_MS", Config.MONGO_SERVER_SELECTION_TIMEOUT_MS),
        Config.MONGO_SERVER_SELECTION_TIMEOUT_MS
    )
    Config.MONGO_CONNECT_TIMEOUT_MS = safe_positive_int(
        env_int("ARL_MONGO_CONNECT_TIMEOUT_MS", Config.MONGO_CONNECT_TIMEOUT_MS),
        Config.MONGO_CONNECT_TIMEOUT_MS
    )
    Config.MONGO_SOCKET_TIMEOUT_MS = safe_positive_int(
        env_int("ARL_MONGO_SOCKET_TIMEOUT_MS", Config.MONGO_SOCKET_TIMEOUT_MS),
        Config.MONGO_SOCKET_TIMEOUT_MS
    )

    # --- 环境变量覆盖：API 分页上限 ---
    Config.API_PAGE_SIZE_MAX = safe_positive_int(
        env_int("ARL_API_PAGE_SIZE_MAX", Config.API_PAGE_SIZE_MAX),
        Config.API_PAGE_SIZE_MAX
    )
    Config.API_USE_ESTIMATED_COUNT = env_bool(
        "ARL_API_USE_ESTIMATED_COUNT", Config.API_USE_ESTIMATED_COUNT
    )

    dns_resolvers_env = env_str("ARL_DNS_RESOLVERS", "")
    if dns_resolvers_env:
        Config.DNS_RESOLVERS = [x.strip() for x in dns_resolvers_env.split(",") if x.strip()]

except Exception as e:
    print("Parse config.yaml error {}".format(e))
    sys.exit(-1)
