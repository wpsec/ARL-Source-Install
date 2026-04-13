## 介绍

> 说明：本目录当前为 ARL 自维护版本，核心兼容 ARL 现有调用协议。  
> 维护说明见 `ARL_MAINTAIN.md`，如与本文档存在差异，以源码与维护文档为准。

WebInfoHunter（简称 wih）工具是一款功能强大、易用性高、扩展性强的命令行工具。

可以快速地获取指定网页中的各种特定信息。采用 Golang 编写。

旨在快速批量地查找指定网页中 JS 中的各种特定信息，例如子域名、路径、URL、邮箱、IP、手机号、AK 和 SecretKey 等。

wih 工具的规则非常灵活，可以根据自己的需求自定义规则，当前已经预设了 36 条规则。

此外，wih 工具还支持对 JWT Token 的有效期进行检验，以及对云 API 中的 AK 和 SK 进行有效性检验，节省验证时间。

wih 工具支持多种输出格式，包括文本、JSON、CSV、HTML 和 Markdown 等，可以根据自己的需求选择合适的格式进行输出。

而且，wih 工具还支持自动根据站点URL保存输出结果，方便对结果来源进行查找，同时还可以将 AK 和 SK 检出结果单独保存，提高工作效率。

当前结构化输出能力：

## 编译

在 `tools/wih` 目录下可直接执行：

```shell
go build -o wih .
```

若希望把 `Go` 构建缓存放到临时目录，避免写入系统默认缓存目录，可使用：

```shell
GOCACHE=/tmp/arl-go-build GOMODCACHE=/tmp/arl-go-mod go build -o wih .
```

编译完成后，当前目录会生成可直接执行的二进制：

```shell
./wih --version
```

## 命令行

```shell
Usage:
  WebInfoHunter（简称 wih） [flags]

Flags:
      --ak-sk-output string        AK/SK 单独保存的文件名（相对文件名默认写入主输出目录） (default "ak_leak.txt")
  -a, --auto-save-name             根据站点自动生成保存的文件名
  -c, --concurrency int            并发数(针对站点) (default 4)
  -P, --concurrency-per-site int   每个站点的并发数 (default 3)
      --csv                        CSV 格式输出
      --dc                         禁止检查 AK/SK 有效性
      --dial-timeout float         Dial timeout (s) (default 5)
      --disable-ak-sk-output       禁止 AK/SK 单独保存
      --disable-check-ak-sk        禁止检查 AK/SK 有效性
      --disable-color              disable log color
      --disable-structured-output  禁止 endpoint/parameter 独立输出
      --endpoint-output string     结构化接口结果输出文件（相对文件名默认写入主输出目录）
  -f, --follow-redirect            跟随重定向
  -G, --generate-rule              生成规则
  -H, --header strings             Custom header (e.g. 'X-My-Header: value')
  -h, --help                       help for WebInfoHunter（简称
      --html                       HTML 格式输出
      --limit-reader-size int      Maximum response size (in bytes) (default 10485760)
      --log-file string            Path to log file (default "-")
  -v, --log-level string           Log level (zero,debug,info,success,error) (default "info")
  -M, --max-collect int            用于表示所有收集类型的最大收集数量, 对于每个站点 (default 600)
      --md                         Markdown 格式输出
  -o, --output string              结果输出文件名或路径(- 为标准输出；相对文件名默认写入 <output-dir>/<域名_时间戳>/；--csv 未指定时默认 result.csv，并自动写成 xlsx 工作簿) (default "-")
      --output-dir string          结果输出根目录（相对文件名默认写入 <output-dir>/<域名_时间戳>/） (default "output")
  -J, --output-json                JSON 格式输出
      --parameter-output string    结构化参数结果输出文件（相对文件名默认写入主输出目录）
  -x, --proxy string               HTTP proxy (e.g. http://localhost:8080)
  -r, --rule-config string         规则配置文件 (default "rules.yml")
      --runtime-enable             启用运行时参数采集（默认启用 Playwright）
      --runtime-driver string      运行时采集驱动(playwright/external/noop) (default "playwright")
      --runtime-command string     运行时采集命令；external 为完整命令，playwright 可覆盖默认 node 调用
      --runtime-timeout int        运行时采集超时(秒) (default 60)
      --runtime-max-actions int    运行时探索最大交互动作数 (default 32)
      --runtime-max-pages int      运行时探索最大页面数 (default 12)
      --runtime-max-requests int   运行时采集最大请求数 (default 180)
      --size int                   设置表格分页大小
  -t, --target string              目标URL或者文件
  -T, --text                       文本格式输出
      --timeout float              Response timeout (s) (default 180)
      --version                    显示版本

```

## 例子

0. 生成规则

```shell
./wih -G
```

2. 对单个URL进行信息提取

```shell
./wih -t https://example.com
```

2. 批量对URL进行信息提取

默认 `--csv` 会直接落盘到 `output/<域名_时间戳>/result.xlsx`

```shell
./wih -t urls.txt --csv
```

如果希望把结果统一写到自定义根目录：

```shell
./wih -t urls.txt --csv --output-dir reports
```

如果你仍然想自定义每个目标目录中的文件名：

```shell
./wih -t urls.txt --csv -o audit.csv
```

3. 第三方程序调用

```shell
./wih -t https://example.com -J -o result.json
```

输出文件将落到：

```shell
output/example.com_20260406_120000/result.json
output/example.com_20260406_120000/result_endpoint.json
output/example.com_20260406_120000/result_parameter.json
output/example.com_20260406_120000/ak_leak.txt
```

4. 独立导出结构化接口与参数结果

```shell
./wih -t https://example.com -J -o result.json \
  --endpoint-output endpoint.json \
  --parameter-output parameter.json
```

5. 默认运行时行为

当前版本默认启用内置 `Playwright` 运行时采集：

- 默认等价于：
  - `--runtime-enable=true`
  - `--runtime-driver=playwright`
  - `--runtime-timeout=60`
  - `--runtime-max-pages=12`
  - `--runtime-max-actions=32`
  - `--runtime-max-requests=180`
- 如果你显式关闭 runtime，`wih` 会提醒你当前未启用 `Playwright` 运行时采集
- 如果本地缺少 `node` 或 Node 版 `playwright` 依赖，`wih` 会提示并自动退回静态扫描
- 若同时传入 `-x/--proxy`，静态抓取请求与内置 Playwright runtime 请求都会走该代理，且都会自动携带 `X-WIH-Target`

6. 使用内置 Playwright 运行时驱动

首次使用前，建议先在 `tools/wih` 目录安装 Node 版 `Playwright` 及浏览器：

```shell
cd tools/wih
npm install
npx playwright install chromium
```

说明：

- `wih` 内置 runtime driver 通过 `require("playwright")` 调用 Node 版 `Playwright`
- 仅安装 Python 版 `playwright` 不足以驱动 `tools/wih/runtime/playwright_driver.js`
- 当前只需 `chromium` 即可，不必下载全部浏览器

安装完成后，可直接使用仓库内置的最小浏览器运行时驱动：

```shell
./wih -t https://example.com \
  --runtime-enable \
  --runtime-driver playwright
```

当前这版内置驱动已覆盖：

- 页面加载期 `fetch/xhr/sendBeacon`
- `WebSocket`
- Playwright 网络请求观测补充
- 基础 `json/graphql/form` body 解析
- 同 host 页面浅层探索
- 少量低风险自动交互：
  - 搜索类输入
  - `select` 切换
  - 低风险 `GET/搜索表单` 提交
  - `tab` 切换
  - 搜索/筛选/下一页/更多 这类按钮点击

`--runtime-max-pages` 现在会真实参与页面探索预算：

- 先访问当前目标页
- 再从 `a[href] / iframe[src] / GET form action` 中收集同 host 候选页
- 按预算做浅层探索，并继续采集运行时请求

7. 使用 external runtime driver 接入自定义浏览器采集器

`WIH` 当前也保留了 external driver 契约。若你有独立的浏览器采集脚本，可通过 `stdin/stdout JSON` 接入：

```shell
./wih -t https://example.com \
  --runtime-enable \
  --runtime-driver external \
  --runtime-command "node runtime_driver.js"
```

`runtime_command` 会从标准输入读取请求 JSON，并向标准输出返回：

```json
{
  "endpoints": [],
  "parameters": []
}
```

注意：

- 当前版本已内置最小 `Playwright` 驱动，同时保留 `external driver` 契约
- 返回结果会继续经过同 host 过滤与统一归并
- 最小可运行示例见：
  - `tools/wih/runtime/playwright_driver.js`
  - `tools/wih/runtime/external_driver_example.py`
  - `tools/wih/runtime/README.md`
  - `tools/wih/runtime/request.example.json`
  - `tools/wih/runtime/response.example.json`

## 内置规则

```yaml
rules:
  # 域名，内置规则
  - id: domain
    enabled: true
  # IP， 内置规则
  - id: ip
    enabled: true
  # 路径，内置规则
  - id: path
    enabled: true
  # URL主机部分为域名，内置规则
  - id: domain_url
    enabled: true
  # URL主机部分为IP，内置规则
  - id: ip_url
    enabled: true
  # 邮箱
  - id: email
    enabled: true
    pattern: \b[A-Za-z0-9._\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,61}\b
  # 二代身份证
  - id: id_card
    enabled: true
    pattern: \b([1-9]\d{5}(19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx])\b
  # 手机号
  - id: phone
    enabled: true
    pattern: \b1[3-9]\d{9}\b
  # jwt token (不要修改ID)
  - id: jwt_token
    enabled: true
    pattern: eyJ[A-Za-z0-9_/+\-]{10,}={0,2}\.[A-Za-z0-9_/+\-\\]{15,}={0,2}\.[A-Za-z0-9_/+\-\\]{10,}={0,2}
  # 阿里云 AccessKey ID (不要修改ID)
  - id: Aliyun_AK_ID
    enabled: true
    pattern: \bLTAI[A-Za-z\d]{12,30}\b
  # 腾讯云 AccessKey ID (不要修改ID)
  - id: QCloud_AK_ID
    enabled: true
    pattern: \bAKID[A-Za-z\d]{13,40}\b
  # 京东云 AccessKey ID (不要修改ID)
  - id: JDCloud_AK_ID
    enabled: true
    pattern: \bJDC_[0-9A-Z]{25,40}\b
  # 亚马逊 AccessKey ID
  - id: AWS_AK_ID
    enabled: true
    pattern: '["''](?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}["'']'
  # 火山引擎 AccessKey ID
  - id: VolcanoEngine_AK_ID
    enabled: true
    pattern: \b(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}\b
  # 金山云 AccessKey ID
  - id: Kingsoft_AK_ID
    enabled: true
    pattern: \bAKLT[a-zA-Z0-9-_]{16,28}\b
  # 谷歌云 AccessKey ID
  - id: GCP_AK_ID
    enabled: true
    pattern: \bAIza[0-9A-Za-z_\-]{35}\b
  # 提取 SecretKey, 内置规则
  - id: secret_key
    enabled: true
  # Bearer Token
  - id: bearer_token
    enabled: true
    pattern: \b[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}\b
  # Basic Token
  - id: basic_token
    enabled: true
    pattern: \b[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}\b
  # Auth Token
  - id: auth_token
    enabled: true
    pattern: '["''\[]*[Aa]uthorization["''\]]*\s*[:=]\s*[''"]?\b(?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}[''"]?'
  # PRIVATE KEY
  - id: private_key
    enabled: true
    pattern: -----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[a-zA-Z0-9\/\n\r=+]*-----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----
  #Gitlab V2 Token
  - id: gitlab_v2_token
    enabled: true
    pattern: \b(glpat-[a-zA-Z0-9\-=_]{20,22})\b
  #Github Token
  - id: github_token
    enabled: true
    pattern: \b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b
  #腾讯云 API网关 APPKEY
  - id: qcloud_api_gateway_appkey
    enabled: true
    pattern: \bAPID[a-zA-Z0-9]{32,42}\b
  #微信 公众号/小程序 APPID
  - id: wechat_appid
    enabled: true
    pattern: '["''](wx[a-z0-9]{15,18})["'']'
  #企业微信 corpid
  - id: wechat_corpid
    enabled: true
    pattern: '["''](ww[a-z0-9]{15,18})["'']'
  #微信公众号
  - id: wechat_id
    enabled: true
    pattern: '["''](gh_[a-z0-9]{11,13})["'']'
  # 密码
  - id: password
    enabled: true
    pattern: (?i)(?:admin_?pass|password|[a-z]{3,15}_?password|user_?pass|user_?pwd|admin_?pwd)\\?['"]*\s*[:=]\s*\\?['"][a-z0-9!@#$%&*]{5,20}\\?['"]
  # 企业微信 webhook
  - id: wechat_webhookurl
    enabled: true
    pattern: \bhttps://qyapi.weixin.qq.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}\b
  # 钉钉 webhook
  - id: dingtalk_webhookurl
    enabled: true
    pattern: \bhttps://oapi.dingtalk.com/robot/send\?access_token=[a-z0-9]{50,80}\b
  # 飞书 webhook
  - id: feishu_webhookurl
    enabled: true
    pattern: \bhttps://open.feishu.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}\b
  # slack webhook
  - id: slack_webhookurl
    enabled: true
    pattern: \bhttps://hooks.slack.com/services/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{15,24}\b
  # grafana api key
  - id: grafana_api_key
    enabled: true
    pattern: \beyJrIjoi[a-zA-Z0-9\-_+/]{50,100}={0,2}\b
  # grafana cloud api token
  - id: grafana_cloud_api_token
    enabled: true
    pattern: \bglc_[A-Za-z0-9\-_+/]{32,200}={0,2}\b
  # grafana service account token
  - id: grafana_service_account_token
    enabled: true
    pattern: \bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b
  - id: app_key
    enabled: true
    pattern: \b(?:VUE|APP|REACT)_[A-Z_0-9]{1,15}_(?:KEY|PASS|PASSWORD|TOKEN|APIKEY)['"]*[:=]"(?:[A-Za-z0-9_\-]{15,50}|[a-z0-9/+]{50,100}==?)"

# 排除规则， 支持字段 id, content, target , source 逻辑为 and ，如果是正则匹配，需要使用 regex: 开头
# source 包括 page(网站首页), js (js 文件), system (系统生成)
exclude_rules:
  # 排除站点 https://cc.163.com 中 类型为 secret_key 的内容
  - name: "不收集 cc.163.com 的 secret_key" # 排除规则名称，无实际意义
    id: secret_key
    target: regex:cc\.163\.com
    enabled: true

  - name: "不收集 open.work.weixin.qq.com 的 bearer_token"
    id: bearer_token
    target: https://open.work.weixin.qq.com
    content: regex:Bearer\s+
    enabled: true

  - name: "过滤来自首页的内容"
    source_tag: page
    enabled: false
```
