# AI智能匹配PoC执行SOP（nuclei + afrog）

## 1. 文档目标

本 SOP 用于指导“AI 智能匹配 PoC”能力落地：
- 基于前期采集的站点信息（指纹、Title、Body、Header、URL、端口服务）判断“该目标优先跑哪些 PoC”。
- 同时支持 `nuclei` 与 `afrog` 两条链路。
- 在保证覆盖率的前提下，减少无效扫描与社区 PoC 写法差异导致的漏召回。

本 SOP 既给研发实现，也给 AI 执行时作为约束协议。

## 2. 当前阶段边界（必须遵守）

- 第一阶段只做“AI决策 + 调度接入 + 配置开关 + 日志评估”。
- 不替换 `nuclei` / `afrog` 引擎本身。
- 不阻断现有链路（AI失败必须 fail-open 回退）。
- **暂不改 `tools/poc/`（后续阶段再推进）**。

## 3. 现网调用机制（As-Is）

### 3.1 nuclei

现网链路：
- 目标构建：`ARL/app/services/commonTask.py` -> `build_nuclei_targets()`
- 扫描执行：`ARL/app/services/commonTask.py` -> `nuclei_scan()`
- 引擎实现：`ARL/app/services/nuclei_scan.py`

当前原理：
- 从 `site` 表读取 `finger/http_server/title`，构造 `finger` 线索。
- 通过 `DEFAULT_FINGER_TAG_MAP`、`FINGER_ALIAS_TAG_MAP`、模板 tag 索引推导 tags。
- 执行 `-tags`，必要时兜底默认 tags（并带智能补全逻辑）。

### 3.2 afrog

现网链路：
- 调用入口：`ARL/app/services/commonTask.py` -> `afrog_scan()`
- 引擎实现：`ARL/app/services/afrog_scan.py`

当前原理：
- 按目标批量执行 `-T` + PoC目录 `-P`。
- 支持 `-s`（关键词）与 `-S`（严重级别），但当前调用基本未做按目标动态收敛。

## 4. 目标能力（To-Be）

引入“Rule First + AI Re-rank”三段式：

1. 规则召回层：
- 先用规则和索引召回候选（防止 AI 漏召回）。

2. AI 重排层：
- AI 读取目标上下文与候选池，做相关性评分与解释。
- AI 只能在候选池中选择，不允许凭空捏造模板/tag/关键词。

3. 执行约束层：
- 白名单校验、数量上限、置信度阈值、fail-open 回退。

## 5. 数据输入规范（Target Context）

每个目标提交给 AI 的上下文字段建议：
- 基础：`target/scheme/host/port`
- 站点：`title/http_server/status_code`
- 指纹：`finger[]`（含来源与置信度）
- 页面：`path signals`、`body tokens`（截断后）
- 服务：`port service/product/version`
- 历史：该目标过往命中摘要（可选）

约束：
- `body` 必须脱敏并截断（建议 2KB）。
- 限制 token 总量，避免单目标成本失控。

## 6. 别名体系（Alias System）

社区 PoC 命名不统一，必须建立 canonical + alias：

实体层级：
- Vendor：如 `Alibaba`
- Product：如 `Canal/Nacos/Sentinel`
- Tech：如 `Spring/Tomcat/Redis`

实现规则：
- 每个 alias 只能归一到一个 canonical key。
- 支持中英文、缩写、连字符/下划线变体。
- 支持厂商与产品联想（如 `Aliyun` -> `Alibaba`）。

示例：
- 识别到 `Alibaba + Canal` 时，应优先召回包含 `Alibaba`、`Canal`、`otter` 等相关 token 的 PoC。
- 对 afrog 可命中 `description: app="Alibaba*"` 及其同义写法。

## 7. PoC知识索引构建

### 7.1 nuclei 索引

离线抽取：
- `template_id`
- `tags`
- `name/description`
- 可提取实体 token（vendor/product/tech）

产物：
- `entity -> tags`
- `tag -> templates`
- `alias -> canonical entity`

### 7.2 afrog 索引

离线抽取：
- 文件路径 token（目录名、文件名）
- `name/title/description` token
- `description` 中 `app="..."`、产品线索

产物：
- `entity -> keywords`
- `keyword -> poc files`

说明：
- 第一阶段执行层可先用 `-s` 收敛。
- 后续再做“按候选 PoC 子集执行”（不在本阶段范围）。

### 7.3 索引脚本（已落地）

- 脚本：`ARL/app/tools/build_poc_index.py`
- 默认输入：
  - nuclei：`/code/tools/nuclei/nuclei-templates`（容器内）
  - afrog：`/code/tools/afrog/afrog-pocs`（容器内）
- 默认输出：`/code/docker/ai/sop/poc_index.json`（容器内）
- 运行命令：

```bash
python3 /code/app/tools/build_poc_index.py
```

可选参数：
- `--nuclei-dir`：自定义 nuclei 模板目录
- `--afrog-dir`：自定义 afrog poc 目录
- `--output`：自定义索引文件路径
- `--with-reverse-map`：附带反向映射（`tag_to_templates/keyword_to_pocs`，仅排障时建议开启）
- `--quiet`：静默模式

运行时接入：
- `ai_poc_scan` 会自动加载索引文件并提取 `token -> tags/keywords` 候选。
- 默认读取：`/code/docker/ai/sop/poc_index.json`（兼容历史路径 `/code/docker/ai/poc-index/poc_index.json`）。
- 可通过环境变量 `ARL_AI_POC_INDEX_FILE` 指定索引文件路径。

### 7.4 索引体积与AI选择机制

- 索引文件可以很大（例如数十万行），但**不会整份发送给 AI**。
- 运行时只做本地检索：
  - 从 `site/finger/title/http_server/url_hints/wih_hints` 抽取 token；
  - 在 `token_to_tags/token_to_keywords` 命中并打分；
  - 仅保留 Top-K 候选（默认 `tags<=48`、`keywords<=48`）。
- 发送给 AI 的候选再限流（默认 `tags<=64`、`keywords<=64`），保证 prompt 可控。
- 默认生成“紧凑索引”（仅运行时必要字段）；反向映射只在 `--with-reverse-map` 时输出。

## 8. AI输出协议（必须严格 JSON）

```json
{
  "target": "https://x.x.x.x:8443",
  "decision": "both",
  "confidence": 0.86,
  "entities": ["vendor:alibaba", "product:canal"],
  "nuclei": {
    "enable": true,
    "tags": ["alibaba", "canal", "default-login"],
    "exclude_tags": ["dos"],
    "reason": "title/body命中canal管理端特征"
  },
  "afrog": {
    "enable": true,
    "keywords": ["Alibaba", "Canal", "otter"],
    "severity": "low,medium,high,critical",
    "reason": "description与app别名命中Alibaba产品族"
  },
  "evidence": [
    "title包含canal",
    "body包含otter/canal",
    "http_server包含nginx"
  ]
}
```

硬约束：
- 必须给证据，不能只给结论。
- `tags` 必须存在于本地白名单。
- `keywords` 必须做字符与长度校验。
- 低置信度不得激进裁剪（默认并集策略）。

## 9. 执行策略

### 9.1 nuclei

- 合并：`final_tags = rule_tags ∪ ai_tags`
- 约束：
  - 去重后上限（建议 <= 18）
  - 空 tags 时回退默认 tags
  - AI失败/超时时完全回退规则链路

### 9.2 afrog

- 先按 `(keywords, severity)` 分组，减少重复进程。
- 执行 `-s` / `-S` 收敛。
- AI不可用时回退现有全量/宽匹配策略。

## 10. AI管理配置接入

在 AI 管理页面新增开关并统一命名：

- 页面区块：`AI功能开关配置`（原“AI去噪配置”）
- 开关1：`启用AI-POC扫描`
  - 配置键：`AI.AI_POC_SCAN_ENABLE`
  - 前端字段：`ai_poc_scan_enable`
- 开关2：`启用AI去噪`（沿用）

触发规则：
- 不在“新建任务”增加 `AI-POC` 独立勾选项。
- 仅当任务启用 `nuclei_scan` 或 `afrog_scan`，且 AI 管理中 `AI_POC_SCAN_ENABLE=true` 时，自动执行 `ai_poc_scan` 决策阶段。

建议运行模式（后续可扩展）：
- `shadow`：只记录建议，不改执行参数
- `suggest`：并集生效（默认推荐）
- `enforce`：高置信度时可收敛

## 11. 风险控制与灰度

必须三阶段推进：
1. Shadow：仅记录 AI 建议与证据。
2. Suggest：小流量启用并集策略。
3. Enforce：仅在高置信度 + 覆盖评估达标后启用。

强制规则：
- `AI_POC_SCAN_ENABLE=false` 时完全不接入 AI 匹配。
- AI异常、超时、返回非法 JSON 必须 fail-open。
- 全程留痕：输入摘要、输出、置信度、执行参数、命中结果。

## 12. 评估指标（验收）

核心指标：
- 真阳率（人工复核）提升
- 单任务扫描时长下降
- 无效结果数下降
- 漏报率不高于基线阈值

建议门槛：
- 真阳率提升 >= 20%
- PoC 扫描时长下降 >= 25%
- 漏报率变化 <= 3%

## 13. 里程碑拆解

M1：索引与别名
- nuclei/afrog 索引构建
- alias 词典归一化

M2：AI协议与校验
- 上下文构建
- JSON schema 校验与白名单检查

M3：调度接入
- nuclei 并集策略
- afrog 关键词分组策略

M4：灰度与评估
- shadow/suggest 上线
- 输出周报与回归策略

## 14. 给AI的执行指令（可直接转Prompt）

你是“PoC调度决策助手”，按以下规则执行：
1. 仅在候选池内选择，不得捏造模板或标签。
2. 所有结论必须引用输入证据（finger/title/body/header/path）。
3. 优先覆盖率，避免激进收敛导致漏扫。
4. 输出必须是严格 JSON，字段齐全。
5. 证据不足时走保守策略并回退。

禁止：
- 输出不可执行参数
- 用未提供事实做断言
- 单一弱证据下给高置信度结论
