# 计划5 附录D · x86 unified 指纹放行 runbook

面向：在真实 x86 服务器（含 Mongo + Redis + 已导入用户指纹的 arl_web 容器）上，
把站点指纹识别链从 `legacy`（旧双路径）灰度切到 `unified`（规范文件+合并视图）。
顺序执行，任一红灯即停在原地、不切换。所有命令在服务器仓库根目录（含 `scripts/`）执行。

> 前置：镜像已含 `app/dicts/site_fingerprints.json.gz`、`service_fingerprints.json.gz`
> （Dockerfile `COPY ARL/app/ app/` 覆盖）。服务映射层默认已生效，无需单独放行。

---

## 门禁 1 · 规则集对照（机器自动对账，必须绿灯）

目的：确认 unified 相对 legacy 的**召回减少**每一条都能归因到误报治理动作，杜绝"解释不了的丢失"。

```bash
docker cp scripts/fingerprint-ruleset-diff.py arl_web:/tmp/fpdiff.py
docker exec -e FINGERPRINT_REAL_DB=1 arl_web python3 /tmp/fpdiff.py | tee /tmp/fpdiff.out
echo "gate1_exit=$?"
```

判读（看输出末尾结论行 + `仅 legacy 有` 段落）：
- 首行必须是 `数据来源: real`。若显示 `preview` 说明 env 没传进去，结论无效，重来。
- `仅 legacy 有` 下每一项都必须是 `[归因：...]`，**不允许出现 `[未归因!!]`**。
- 结论行出现"禁止放行 unified" → **红灯，停止**，把 /tmp/fpdiff.out 贴回讨论。
- 结论行"减少全部可归因" 且 `gate1_exit=0` → 绿灯，进门禁 2。

含义：legacy 生效规则 = Mongo 用户规则 + kscan 内置(7239)；unified = 基线 gz(webapp+finger+kscan_local，已去泛化) + Mongo overlay。
差异只允许两个方向：unified 更多（faviconhash/1930 webapp/1760 kscan_local 进链，正常）、
或 unified 更少但每条是 policy 主动删的泛化噪声（可接受）。出现第三种＝bug。

## 门禁 2 · 人工复核拒绝名单（5 分钟）

目的：误报治理会主动删掉"整条规则都是通用短词"的应用。这些是真实产品名，删除=以后识别不出，
需要你确认"宁可不要"，或对可惜的补一条更具体规则。

查看本次被整条拒绝的应用（真实数据下比本地预览多，含 finger 源）：
```bash
docker exec arl_web python3 - <<'PY'
import gzip, json
d = json.load(gzip.open("/code/app/dicts/site_fingerprints.json.gz"))
rej = d["meta"].get("rejected_rules_detail", [])
from collections import Counter
by = Counter(r["reason"] for r in rej)
print("拒绝总数:", len(rej), dict(by))
for r in rej[:80]:
    print(" -", r["name"], "|", r["reason"], "|", ",".join(r.get("sources", [])))
PY
```

对每个你觉得"其实想识别"的产品：在 Web「指纹管理」页新增一条规则，
`human_rule` 写**足够具体**的特征（避免又是 login/后台这类泛词，否则照样被拒），例如：
`body="specific-js-hash" || title="某产品登录系统"`。保存后经 Redis 版本联动，
unified 侧最迟 60s（Redis 开启）自动纳入，无需改代码。

补规则后重跑门禁 1，确认该名称已从"仅 legacy 有 / 拒绝名单"消失或转为可解释。
复核无异议 → 绿灯，进门禁 3。

## 门禁 3 · unified 灰度观测（几天真实任务）

切换（先确认 Redis 已启用，否则 overlay 不热更新，见"注意"）：
```bash
# 已有该键时一条命令改值：
grep -q SITE_FINGERPRINT_SOURCE ARL/docker/config-runtime.yaml \
  && sed -i 's/.*SITE_FINGERPRINT_SOURCE.*/  SITE_FINGERPRINT_SOURCE: "unified"/' ARL/docker/config-runtime.yaml \
  && echo "已切换 unified" || echo "键不存在：请手工编辑"
```
键不存在时**手工编辑** `ARL/docker/config-runtime.yaml`，在两空格缩进的 `ARL:` 段内
（与 `API_LIST_CACHE_EXPIRE` 等同级）加入 `  SITE_FINGERPRINT_SOURCE: "unified"`
——不要 `>>` 直接追加到文件尾（可能挂到 CELERY 等其它顶层段下）。
改完校验一次再重启：
```bash
grep -A20 "^ARL:" ARL/docker/config-runtime.yaml | grep SITE_FINGERPRINT_SOURCE
docker compose -f ARL/docker/docker-compose.yml config -q && echo "yaml ok"
```
然后重启生效：
```bash
docker restart arl_web arl_worker_1 arl_worker_2 arl_scheduler   # worker/scheduler 均加载指纹，需全重启
```

观测窗口内跑若干**含多样目标**的真实任务，比对站点识别结果：
```bash
# 近 N 条任务的 finger / finger_candidates 采样，肉眼 + 频次看两件事
docker exec arl_mongodb mongosh arl --quiet --eval '
db.site.find({}, {site:1, finger:1, finger_candidates:1}).sort({_id:-1}).limit(50).forEach(d=>print(d.site, JSON.stringify(d.finger||[]), "|cand:", JSON.stringify(d.finger_candidates||[])))'
```
放行标准（三条全中才转正）：
1. `finger` 里不再冒出"后台/登录/首页"这类通用词造成的误报；
2. 已知该识别的资产（你补的规则、主流 CMS/中间件）正常出现在 `finger` 或 `finger_candidates`；
3. 无异常集中：某单个应用名霸屏绝大多数站点＝疑似泛化规则漏进，回门禁 2 处理。

任一不满足 → 回滚（见下），不强行转正。

## 回滚（随时，一条配置）

`unified` 出任何问题，改回 `legacy` 即恢复旧双路径，旧加载路径在第 7 阶段前**始终保留**：
```bash
sed -i 's/.*SITE_FINGERPRINT_SOURCE.*/  SITE_FINGERPRINT_SOURCE: "legacy"/' ARL/docker/config-runtime.yaml
docker restart arl_web arl_worker_1 arl_worker_2 arl_scheduler
```
站点 unified 与"文件缺失即降级 legacy"是内置行为：即使忘记改配置，
只要 `site_fingerprints.json.gz` 不可读，`fetch_fingerprint` 会自动走 legacy（日志有
`unified site fingerprint unavailable, fallback to legacy`）。服务映射层是纯增强面，
文件缺失自动透传，无需回滚。

## 注意 / 已知约束

- **Redis 必须开启**：unified 的用户规则热更新靠 `arl:fingerprint:unified:ver` 版本联动。
  `REDIS_ENABLE=false` 时改用户规则要重启进程才纳入（overlay 不热重建）。生产开 Redis 即无感。
- **指纹文件不可进 Git 的旧文件**：`kscan_fingerprint.local.json` 被 `.gitignore` 忽略，
  但它已编译进 `site_fingerprints.json.gz`（meta.input_files 记录了它的 sha256 作可复现凭证），
  镜像与运行期都不依赖该明文在位。
- **finger.json 种子删除复活**：用户在 UI 删除 finger.json 来源规则后，重启容器 sync-fingerprint
  会 upsert 回 Mongo（legacy 既有语义，本次未改）。要"删了不复活"是独立需求（墓碑机制），另立项。
- **第 7 阶段（删旧文件/旧加载路径）不在本 runbook**：只有门禁 1-3 全绿且稳定运行一个观测周期后才评估，
  且删除前须 `grep` 全仓确认无 `web_app_rule`/`finger.json`/`kscan_fingerprint` 运行时引用。
- 放行通过后，把门禁 1 的 `/tmp/fpdiff.out` 与门禁 3 采样片段归档进 docs/plan/03 对应批次，作为
  "有效结果不减少、低证据不再直接确认"的验收证据（05 §九）。
