# 05 附录B · local 增量审计报告（第2阶段A，决策1前置）

- 生成命令：`python3 scripts/fingerprint-local-audit.py`（重跑刷新）
- 对比对象：`ARL/app/dicts/kscan_fingerprint.json`（7239 条） vs `ARL/app/dicts/kscan_fingerprint.local.json`（9673 条）

## 一、增量定义与规模

- 名字新增（进生产的净新增面）：**1760** 个应用 / 1807 条规则条目
- 同名但 human_rule 被 bundle 强化/合并（内容差异）：**2295** 个应用
- kscan 独有而 local 缺失：**0**（预期 0，非 0 即 bundle 丢规则，必须阻断）

## 二、新增规则静态审计

- 字段分布：`{"body": 2564, "header": 446, "icon_hash": 193}`
- 单条件且字面量<8（泛化高风险，按 §五误报控制只能进候选）：**39**
- 字面量长度<5（疑似噪声，建议生成期拒绝或降级）：**19**
- 与 webapp 重名（合并时同名规则 sources 会叠加，预期行为）：364 个
- 与 finger.json(Mongo 种子) 重名：1146 个

### 同名强化样例（前 5）
```text
app=04webserver
  kscan: title="04WebServer"
  local: title="04WebServer" || body="04WebServer" || header="04WebServer"
app=08cms
  kscan: body="typeof(_08cms)" || body="content=\"08cms"
  local: body="content=\"08CMS" || body="typeof(_08cms)" || body="typeof(_08cms)" || body="content=\"08cms" || body="content=\"08cms" || body="typeof(_08cms" || body="ty
app=1039jxt
  kscan: title="1039_jxt"
  local: title="1039_jxt" || body="1039_jxt"
app=1039家校通
  kscan: title="1039家校通"
  local: title="1039家校通" || body="1039家校通" || header="1039家校通"
app=115cms
  kscan: body="115CMS" || title="115CMS"
  local: body="115CMS" || title="115CMS" || body="115CMS"
```

## 二点五、超集校验与泛化噪声清单

- 同名应用全量校验（7023 个）：kscan 字面量在 local 丢失的应用 **0** 个 → bundle 合并只增不减，通过
- 新增规则命中泛化单字（stopword 表：['admin', 'error', 'home', 'index of', 'login', 'server']…）：**4** 条，生成脚本第2阶段必须对其拒绝或强制候选降级：
```text
  GROWATT 系统 :: body="login"
  H3C-ER3100[+]默认密码admin/adminer3100 :: body="login"
  HUAWEI-S5730 :: header="server"
  HUAWEI-S7700 :: header="server"
```

## 三、golden 双文件对比（12 合成样本 × 识别明细差异）

- `cisco_login`：新增 ['GROWATT 系统|74']；消失 []
- `hikvision`：新增 ['HUAWEI-S5730|82', 'HUAWEI-S7700|82']；消失 []

## 四、裁决输入

- 阻断项：kscan 独有非 0、新增规则里短字面量异常多、golden 出现命中**消失**（bundle 不应丢条件）。
- 通过项定义：无阻断 + 泛化噪声清单（二点五节）在生成脚本中被拒绝/降级 + 观测期（x86 真实任务）新增确认名称无异常聚合。

## 五、审计结论（2026-09-04 实测）

- 全量超集校验通过（0 丢失）；removed=0。
- golden 新增命中 3 条（GROWATT 系统、HUAWEI-S5730/7700）全部由 `body="login"`、`header="server"` 类单词泛化规则产生，置信度 74/82 均落在候选档（<85 不确认）——**证实增量收益（1760 召回）与噪声并存，纳入生产的前提是生成脚本落地泛化拒绝/降级**，这正是第2阶段的核心工序。
- 建议：按决策1 纳入 local 基准，第2阶段生成脚本实现二点五节噪声清单的确定性拒绝规则；观测期专项核对该清单名称是否仍出现在候选 Top。
