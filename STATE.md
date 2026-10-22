# STATE — capkit 当前状态台账

> 每次开工前先读这个文件。每次收工前更新它。
> 长线里程碑定义见 `docs/ROADMAP.md`，本文件只记录实际进度。
> 只写事实和状态，不写计划感想。状态只有三种：DONE / DOING / TODO。

当前里程碑：**M2 会话与身份闭环 — DONE**（Exit 四项实测通过，已推送 origin/main）；M1 因真实凭据缺失保持 DOING

## 解冻（2026-10-20）：4zrec 重新接入 runtime.Call — 新增漏洞情报与产物生成能力

- **解冻依据**：冻结条件写的是「出现第二个真实宿主，或 4zrec 重新接入 `runtime.Call`」。
  实测 4zrec 已满足：`internal/capkitbridge/bridge.go` 引入 `capkit/runtime` 并调用
  `rt.Call`（bridge.go:201 `capruntime.New`、:234/:394 `b.rt.Call`），`go.mod` 依赖
  `capkit v0.4.12`。冻结解除，M3–M9 仍不启动（本次不是里程碑，是能力补齐）。
- **交付内容（DONE）**：新增 3 个 kit + 2 个端口，`bash scripts/verify.sh` 全绿，
  契约工具覆盖从 81 涨到 **97**。
  - 端口：`core.IntelStore`（Upsert/Query/Get，宿主拥有 schema 与去重键）、
    `core.Completer`（`Complete(ctx, system, user, maxTokens)`，宿主映射模型配置）。
    两者都加进 `core.Deps`、`Registry.Validate` 的可用表与 `runtime.Config`。
  - `kits/vulnintelkit`（4 工具）：9 个公开情报源（KEV/OSCS/长亭/奇安信/微步 JSON，
    AVD/Seebug/启明星辰/Struts2 页面解析）+ 严重度门槛 + 按唯一键幂等入库 + 检索。
    单源失败隔离，不阻断其余源。
  - `kits/pockit`（5 工具）：情报 → 结构化分析 + 可运行验证 PoC、nuclei 模板草稿、
    资产指纹规则草稿、按要素重建脚本；`poc_publish` 才是写库那一步（高风险，走审批门禁）。
    **模板骨架由代码生成，模型只补请求路径**；缺少可匹配特征时报错而不是产出噪音模板。
    **PoC 同样是骨架代码生成**（2026-10-20 补齐，见下条）。
  - `kits/bindingkit`（3 工具）：指纹产品名 → 模板库规范产品键的显式绑定，
    `binding_check` 回答「已识别 X，能对这台机器跑 Y 模板吗」。
  - harness 补齐 `Intel`/`Completer` 假件；`sdk-allowlist.txt` 加
    `kits/pockit gopkg.in/yaml.v3`；DEPENDENCIES.md/README 同步。
- **PoC 改为要素填充（DONE，2026-10-20）**：原先 `poc_generate` 让模型直接写整段
  脚本，与 4zrec 侧并发完成的 `pocgen.go` 相比是更弱的做法——模型写出的脚本端点、
  参数、判定特征常是编的，格式对但跑不通。现在模型只产出 `poc_spec`
  （path/method/params/body_format/marker/match_status/evidence/constructible），
  脚本由 `kits/pockit/pocscript.go` 拼装，并强制接地校验：
  - 入口路径必须非 `/` 且在情报原文里出现（整段或末段 ≥4 字符）；
  - 响应特征必须能在原文里找到出处，或给出合法状态码 —— 两者都没有就不产出脚本；
    要素不全时返回 `poc: null` + `poc_note` 说明原因，而不是退化成空壳脚本；
  - 参数名不接地只降级为 `poc_note` 提示（文档化的端点用显而易见的名字是合理的）；
  - 脚本只用标准库（`urllib`），不依赖 `requests`，保证在目标侧机器上能跑；
  - 新增 `poc_script_build`：人工改完要素后不调模型重建，接地规则同样生效。
  单测包含 `python3 -m py_compile` 实编译校验（环境无 python3 时 skip）。
  **口径**：实现是按 4zrec 的设计思路重写的，未拷贝其 AGPL 源码。
- **口径（不许含糊）**：9 个源的**协议实现是重写的**，不是从 4zrec 拷贝——4zrec 是
  AGPL-3.0，capkit 是 Apache-2.0，拷贝会污染许可。只参考了端点与字段这类协议事实。
- **live 验证（DONE，2026-10-20）**：加了 `go test -tags live -run TestLiveSources`，
  用真实 `httpx.Fetcher` 对 9 个源各抓 10 条。**首跑 4/9 可用**，5 个源是坏的，逐个查
  真因并修掉（每一条都有对应单测，fixture 是真实响应的裁剪副本）：
  - chaitin：分页循环触发 WAF，第 4 页起回 HTTP 465 的 HTML 挑战页。改成每轮只抓一页
    （feed 是 newest-first，周期轮询不需要翻页），并对 465/403/429 做一次退避重试。
  - qianxin：`status=10000` 被当成错误码（其实是 success）；只读 `key_vuln_add`
    （1 条）而不是 `vuln_add`（实测 76 条），一天的情报丢了 98%。
  - threatbook / qianxin：严重度只认「高危/中危/低危」，不认情报源用的「高风险/
    中风险/低风险」，导致全部落成 unknown、过不了严重度门槛。
  - seebug：解析 `/vuldb/vulnerabilities/`，实际链接是 `/vuldb/ssvid-<id>`；标题取的是
    第一个 anchor（SSV id）而不是 `class="vul-title"` 那个；等级没从 `data-original-title`
    读，CVE 和 PoC 标记整行漏掉。
  - struts2：Confluence 改版，列表页现在只有 `/confluence/spaces/WW/pages/<id>/S2-00N`
    链接、无标题；改为读列表页 + 逐条抓详情页取 title/CVE/severity。
  - venustech：详情页不再是「漏洞名称/CVEID/漏洞等级」两列表格，改成分节正文且**没有
    等级字段**。等级如实报 unknown（不靠措辞猜），详情页抓不到时用列表页的标题+日期
    降级保留条目——否则 403 限流会让源「看起来没更新」。
  - **还发现一个此前没测出来的真 bug**：`uniqueKey(source, key)` 参数顺序与所有调用点
    相反，产出的是 `chaitin_CT-...` 而不是 4zrec 已在用的 `CT-..._chaitin`。直接切换
    会让每条情报在新键下重新插一行。已修正并加单测钉住。
  - **aliyun-avd 改为宿主提供（DONE，2026-10-20）**：该站对所有路径（列表/详情/
    猜的 /api/*）返回同一个约 27KB 的 JS 混淆挑战页，页面数据由脚本算出的签名参数
    `?timestamp__NNNN=` 现场拼出来，普通 HTTP 客户端拿不到。读它需要 JS 引擎——
    那是本库不该为一个源背的运行时依赖，也是不该开在库里的远端代码执行面。
    因此 **capkit 不再内置 AVD**，改为新增端口 `core.IntelSource`
    （`Name() + Fetch()`）和 `core.Deps.ExtraIntel`：宿主用自己的机制抓源，capkit
    把它并进同一个 poll 循环、同一个去重键和严重度门槛。
    4zrec 侧用现有的 goja 方案实现该端口，实测 5 条 AVD 情报端到端入库
    （`AVD-2026-104935_aliyun-avd`），键格式与存量数据一致。
  - 复跑结果：capkit 内置 **8/8 可用**（AVD 不再计入内置源）；宿主接入 AVD 后
    整体 9/9。
- **待办**：4zrec 侧把源层切到 capkit（bridge 注册 + IntelStore/Completer 适配已 DONE，
  见下），本地 `grab/analyzer/tplgen/fpgen/pocgen` 的删除**尚未执行**：capkit 的 9 个源
  未经真实网络验证，且两边 `unique_key` 生成规则不同（4zrec 存源内原始 id，
  capkit 是 `<id>_<source>`），直接切换会重复入库或缺行。切换方案见 4zrec
  `docs/capkit-swap-plan.md`。

## 冻结（2026-10-19）：M2 为最后一个交付里程碑

- **状态：FROZEN**。M3–M9 不启动，`docs/ROADMAP.md` 保留不删。
- **冻结依据（事实）**：唯一宿主 4zrec 于同日回退到 `v0.5.0`，其 `go.mod` 不再引用 capkit，
  全仓 `runtime.Call` 调用点为 0。当前无消费方。
- **已交付**：8 个 kit 曾被 4zrec 真实 import（shellkit / spacemapkit / credkit /
  enterprisekit / playbookkit / exploitkit / icpkit / githubkit）。其余 17 个 kit 从未有
  宿主消费，状态记为 frozen-unverified，不删、不再加功能。
- **契约层口径**：`runtime.Call` 的四处机制（门禁 / 结果信封 / 证据分离 / 幂等作业）
  从未被任何宿主接入，属未验证能力，不得对外表述为已验证。
- **M1 口径**：因缺真实云凭据保持 DOING，随冻结一并永久挂起，不构成未完成项。
- **解冻条件**：出现第二个真实宿主，或 4zrec 重新接入 `runtime.Call`。解冻时先读本节，
  再按 `docs/ROADMAP.md` 的顺序约束继续。

## 阶段 0（2026-10-19 13:2x）：上一会话遗留改动已提交并推送

上一会话遗留的未提交改动（cloudkit 测试补齐 + 门禁缺陷修复 + gofmt）已按语义分 3 个
提交推送：`be080b7`（门禁缺陷修复）、`b2eec59`（测试补齐）、`4bdfb9f`（gofmt 全仓）。
`origin/main` 已从 `3689232` 推进到 `4bdfb9f`，本地不再领先。

另外发现并修掉一个 CI 门禁缺陷：`gofmt -l .` 此前是红的（6 个文件，其中 3 个是既有
文件 `contract_ci_test.go`、`kits/reconkit/capability_test.go`、`kits/cloudkit/aliyun_test.go`），
verify.sh 不跑 gofmt 所以一直没暴露。已全仓 gofmt，CI 的 gofmt 门禁转绿。

## M1 挂起项（不许含糊）

**M1 除「四家云真实凭据验证」外全部达标。**

- **M1 挂起项 = 真实凭据验证（未验证，缺凭据）**：四家云
  `cloud_ak_verify` / `cloud_asset_list` 各需真实 AK/SK 跑通一次，本机
  `CAPKIT_CLOUD_*` 环境变量数量为 **0**，该项是**外部凭据阻塞**，不是代码问题。
- **离线假件测试不等价于真实调用**：四家云的离线假件测试全 PASS（cloudkit 覆盖率
  83.2%），但那是喂给注入 `HTTPDoer` 的厂商线格式样本，**不等于**向真实云 API 发起
  签名请求。未做过真实验证，就不写「已验证」。
- 未伪造任何 AK/SK，未把离线测试写成真实验证。
- M1 因此保持 **DOING**（不因 M2 达标而置 DONE）。

## 二、M2 会话与身份闭环 — Exit 四项真实回显（2026-10-19 实测）

靶机：`capkit-lab:latest`（`examples/lab/php/Dockerfile`，`FROM php:8.2-apache`），
端口 `127.0.0.1:18080 -> 80`（避开 7890/8787/8788/9090/11434/5433/8082/19090），
容器名 `capkit-lab`，仅绑 loopback。命令：
`docker build -t capkit-lab:latest examples/lab/php` →
`docker run -d --rm --name capkit-lab -p 127.0.0.1:18080:80 capkit-lab:latest`。

四项均由 `go run ./examples/*` 走**公开契约**（runtime.Call）实测，非单测、非推理。

**Exit-1：`cmdi_probe` 命中且 `cmdi_execute` 拿到 `id`** — 见 `examples/webshell-chain` 步骤 1–2：

```
status: success | summary: 命令注入已确认（technique=echo）：响应出现唯一标记 example_cmdi_marker（状态 200）
confirmed with payload: {{value}};printf example_cmdi_marker
execution template: {{value}};{{cmd}}
status: success | summary: cmdi_execute 执行完成（status 200）
response preview: PING 127.0.0.1
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

（cmdi_execute 的响应体按 §5.5.4 只进证据库，上面是证据 preview；`uid=33(www-data)`
是真实执行结果。注意 probe 的 payload 是 `printf <marker>` 型的**证明**载荷，
不能直接当 `{{cmd}}` 模板用，示例用 `deriveTemplate` 只取它验证过的分隔符。）

**Exit-2：`webshell_deploy` 落地后 `session_open(kind=webshell)` + `session_exec` 拿到 `id`**
— 同示例步骤 3–5：

```
status: success | summary: 已在 http://127.0.0.1:18080/wcd438a7c.php 落地 php shell（模板 php-system-min，sha256 5240f7a20c56…）
cleanup: rm -f /var/www/html/wcd438a7c.php
status: success | summary: 已打开 webshell 会话 sess-1792392827454760951-1（127.0.0.1）
status: success | summary: 会话 sess-1792392827454760951-1 执行完毕（exit 0，54 字节）
output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

（投递是转成 base64 后经同一个命令注入点写入 `/var/www/html` 的，即真正
「漏洞 → 落地」；`id` 由落地的 PHP shell 经 Apache 执行返回。）

**Exit-3：带登录态目标上 `Identity.Headers()` 自动带 Cookie，服务端识别为已登录**
— 见 `examples/identity-login`，靶机同一容器的 `/login.php` + `/userinfo.php`：

```
status: success | summary: 已在 http://127.0.0.1:18080 登录（kind=form，身份 alice，作用域 127.0.0.1）
headers: Cookie: 1 value(s)
cookie names: PHPSESSID
GET http://127.0.0.1:18080/userinfo.php -> 200 {"authorized":true,"user":"alice"}
--- 对照（匿名）---
GET http://127.0.0.1:18080/userinfo.php (anonymous) -> 401
```

**Exit-4：清理命令删掉落盘件后目标恢复原状** — 同示例步骤 6：

```
cleanup via session: success | 会话 sess-1792392827454760951-1 执行完毕（exit 0，0 字节）
after cleanup, GET http://127.0.0.1:18080/wcd438a7c.php -> 404
session_close: success | 会话已关闭: sess-1792392827454760951-1
```

靶机清理状态（实测 `docker exec capkit-lab ls -la /var/www/html/`）：只剩
`exec.php` / `login.php` / `userinfo.php` 三个原始文件，`find … -name 'w*.php'` 计数为
**0**，无落盘残留。清理是通过会话内执行工具返回的 `cleanup.command` 完成的，
再用 `http_probe` 从目标视角确认落盘 URL 已 404（比宿主文件系统检查更可信）。

## M2 四条任务（全部 DONE）

- [x] **M2-1 identitykit 工具化**：新增 `kits/identitykit/capability.go`，
  声明并实现 `identity_login`（调宿主注册的 AuthFlow，出参 user/hosts/label）、
  `identity_csrf`（GET 页面抽 token，返回 name/token/source）、
  `identity_token_check`（吃 TokenSnapshot，返回 needs_refresh 与依据）。
  现有导出 API 与测试未动（只新增 `ExtractCSRFWithSource`）。README 原写
  「契约包，无工具」，与 ROADMAP 冲突；**按 ROADMAP 执行**（偏离见下）。
- [x] **M2-2 AuthFlow 注册机制**：`kits/identitykit/registry.go` 的
  `AuthFlowRegistry` 按 kind（form/json/oauth/cas/bearer）注册查找，
  `RegisterSite(kind, fn)` / `RegisterFormSite(FormFlow)` 一行装配；
  同 kind 重复注册报错（静默覆盖会把凭据发到错误站点）；多站点共用一个 kind
  时按 `Credentials.Fields["target"]` 分派。单测覆盖「未注册 kind 报错」
  （tool_missing，Hint 带已注册 kinds）与「注册后被 identity_login 调用」。
- [x] **M2-3 WebShell 会话接 sessionkit**：`all.RegisterWebShellOpener(mgr, exec)`
  一行把 `shellkit.WebShellOpener` 装进 `sessionkit.Manager` 的 kind=webshell
  （放 all/ 是因为要同时 import 两个 kit，而 kit 之间禁止互相 import）。
  `all/webshell_session_test.go` 起真实 HTTP 靶，经 Manager → runtime.Call 走完
  session_open/exec/upload/download/close，不只测 adapter。
- [x] **M2-4 「漏洞 → WebShell 落地 → 会话接管」**：`webshell_deploy`
  （RiskHigh，走 approval）＝ `payload.Generate` + 宿主 `WebShellDeployer`，
  出参落点 URL、可直接喂 `session_open` 的 webshell 参数、清理命令。
  `examples/webshell-chain` 串起 cmdi_probe → cmdi_execute → webshell_deploy →
  session_open → session_exec，只走公开契约。

## M2 期间的偏离与顺带修复（都记在这里）

1. **identitykit 从契约包变成带工具的包**：与 `kits/identitykit/README.md` 原文
   「契约包，无工具」冲突。ROADMAP M2 任务 1 明确要求「identitykit 注册成工具」，
   以 ROADMAP 为准，README 与 `docs/STATUS.md` 已同步改写。
2. **identitykit 不进 RegisterFull**：它的 flow registry 是宿主注入的协作者
   （同 enterprisekit 的 resolver），`core.Deps` 装不下，因此由
   `all.RegisterIdentity(reg, flows)` 单独注册，contract_ci_test 的
   `argKitRegistration` 里带参登记（契约覆盖含它的 3 个工具）。
3. **收紧 WebShell 宿主 Executor 契约（修复静默数据损坏）**：
   `kits/shellkit/session/adapter.go` 的 `Download` 原先把返回体剥掉非字母表字符后
   做 base64 嗅探，于是纯文本 `abcdefgh`（8 字符）或 `payloadbytes`（12 字符）
   会被解成 6/9 字节垃圾，`session_download` 回报的 sha256 与实际文件内容不符。
   改为显式契约：`session.ExecResult` 新增 `Encoding` 字段，只有宿主声明
   `"base64"` 才解码，未声明一律原样；声明了但解不开则报错而不是返回垃圾。
   **这是行为变更**：未声明 base64 的宿主会从「被猜着解码」变成「原样返回」。
   主机侧改动仅 `kits/shellkit/session_test.go` 与 `session/adapter_test.go` 两处
   测试假件补 `Encoding:"base64"`（它们本来就是 base64，语义未变）。
4. **修复 FormFlow 不带 cookie 导致带 CSRF 的表单登录必然失败**：
   登录页设置的会话 cookie 从来没随 POST 发出去（headers 里只有 Content-Type），
   而 CSRF token 通常绑在该 cookie 上（PHP/Django/Rails 皆然），于是服务端一律
   回 `bad csrf`。修法：POST 前把 jar 的 Cookie 一并带上。**这是实测发现的**——
   第一次跑 Exit-3 就是 403，手工 curl 对照（带 jar 成功、不带 jar 失败）定位到它。
   `TestFormFlowLogin` 增加断言钉住。
5. **memshell 的 DeployPlan/Deployer 仍未注册成工具**：M2-4 要的是**文件型**
   webshell 落地（`payload.Generate` + 宿主 Deployer），而 memshell 是内存马路径，
   前提是已有一个 webshell 会话（`DeployPlan.Session`），属于 M4 容器/中间件范畴，
   M2 未纳入。列为 TODO 而不是当作已完成。
6. **CI 门禁补强**：`gofmt -l .` 此前为红（见阶段 0）；两个新示例已加入
   `.github/workflows/ci.yml` 的 Examples 步骤。

## M2 代码与工具注册现状（实测）

- 契约工具数：**81 → 85**（+ identitykit 3，+ shellkit webshell_deploy 1）。
  `bash scripts/verify.sh` 输出 `contract coverage 85 tools`，0 失败。
- 覆盖率（`go test -cover ./kits/...`）：`identitykit` 78.4%、`shellkit` 68.6%、
  `shellkit/session` 87.5%、`shellkit/payload` 92.1%、`cloudkit` 83.2%；
  `kits/shellkit/plan` 无测试文件（无 `0.0%`，不触发 CI 的 0% 门禁）。
- 门禁顺序与语义未改：仍为 scope → approval → ratelimit → audit。
- 未新增任何第三方依赖（`go.mod` 未变，`check-imports.sh` 白名单未变）。
- kit 之间零交叉 import，组合只在 `all/` 与 `examples/`。
- 未实现平台侧认证（登录与 RBAC 仍归宿主）。

更新时间：2026-10-19


## 一、项目目标（不可漂移）

capkit 是**纯后端 Go 库**，通用渗透能力集合，供其他项目 import 复用。

- 不做 UI、不做平台、不做发现层重造
- 整体交付，不承诺单 kit 独立可用
- 目标覆盖：信息收集 → 漏洞发现 → 利用 → 凭据 → 后渗透 → 维持 → 清理 → 免杀投递 → 内网 → AD → C2 → 云

完整能力规划见 `docs/究极渗透能力包实现方案.md`，第一章写边界，第四章写能力矩阵，第十章写 v2 扩展。

## 二、硬验收（每次提交前必须跑）

```bash
bash scripts/verify.sh
```

任何一项失败，任务就不算完成。不要用"基本完成""已实现主体"描述状态。

## 三、当前进度

### DONE

- [x] 契约层：`Capability`、`Port`、`Result` 信封（六态 Status / Summary / Findings / Evidence / Next / Page / Error / Meta）
- [x] 门禁：scope → approval → ratelimit → audit，四道强制
- [x] `Registry` 静态声明、`Runtime` 实例容器（无 Register 方法）
- [x] kit 零交叉 import，`scripts/check-imports.sh` 通过
- [x] `harness` 假件：HTTP、Process、Clock、IDs、Audit、Sessions、CloudSigner
- [x] `contract_ci_test.go` 走 `runtime.Call`，契约覆盖 **85 个工具**（M2 后），断言 Status/Summary/Meta/Error
- [x] exploitkit 11 个工具注册
- [x] shellkit 工具注册（M2 后 8 个：会话 open/exec/upload/download + tunnel_open + list + close + webshell_deploy）
- [x] containerkit 检测与计划（kubelet / apiserver / etcd / docker-api / escape-check / escape-plan）
- [x] internalnetkit 基础探测（local-info / host-discovery / portscan / domain-info / smb-shares）
- [x] latkit 8 个工具（psexec / wmiexec / smbexec / winrm / pass-the-hash / kerberoast / asrep / dcsync）
- [x] persistkit（enum / plan / apply）、cleanupkit（preview / apply）
- [x] cloudkit AWS 完整实现（ec2 / iam / rds / s3 / ssm，573 行，真调 SDK）
- [x] cloudkit 阿里云 / 腾讯云完整实现（真调 SDK，离线假件测试全 PASS）
- [x] cloudkit 华为云接线（`huawei.go` 740+ 行，真调 `huaweicloud-sdk-go-v3`）：
  `cloud_ak_verify`（STS `GetCallerIdentity`）、`cloud_asset_list`（ECS `ListServersDetails`
  + RDS `ListInstances`，project_id 交由 SDK 经 `region.NewRegion` 解析）、
  `cloud_iam_list`（IAM v3 `KeystoneListUsers` / `KeystoneListPermissions` /
  `ListPermanentAccessKeys`，外加有界的组权限管理探测）。
  `cloud_storage_list` / `cloud_run_command` 诚实返回 `unsupported` 并写明原因
  （OBS 走独立的 `huaweicloud-sdk-go-obs`，未引入；ECS v2 无云助手 API），不伪造能力。
  签名、分页、重试全部交 SDK。
- [x] cloudkit 注册：`all.RegisterCloud` 已加并接入 `RegisterFull`；
  `contract_ci_test.go` 的 `kitRegistration` 增加 `cloudkit` 项 →
  **契约覆盖 76 → 81 工具**。
- [x] 依赖登记：`DEPENDENCIES.md` 补齐 22 条云 SDK（名称 / 版本 / 许可证 / 用途，
  全 Apache-2.0，腾讯 COS 为 MIT，无一在 copyleft 名单）。
- [x] `docs/` 四份文档：实现方案、工具调用协议、宿主接线指南、前端展示设计方案

### DOING

- [ ] **M1：四家云真实凭据验证（阻塞中）**：本机 `CAPKIT_CLOUD_*` 数量为 0 →
  **未验证 — 缺真实凭据**，外部凭据阻塞。这是 M1 唯一未达标项，因此 **M1 保持 DOING**
  （M2 达标不影响 M1 状态）。
- [x] **M2：会话与身份闭环 — DONE**（Exit 四项已全部实测通过，见本节；
  提交 `4e9b5c0` / `86dae35` / `3488a59`，台账 `f7b4acd`，已推送 origin/main）。

### DONE（本会话 T4–T8 收尾）

- [x] **Summary 全量接入**：契约层 `runtime` 统一补 `Summary` 兜底，
  `contract_ci_test.go`（`TestContractEnvelope`）断言每个工具返回非空、非泛化
  `Summary`、正确 `Status`/`Meta`/`Error`。当时覆盖 76 工具，M2 后 85 工具全 PASS。
  internalnetkit、icpkit、reconkit、oastkit、verifykit 等已改。
- [x] **spacemapkit Manifest**：`space_search`/`space_domain_search`/`space_providers` 三工具
  Manifest 已有，符合文档要求。
- [x] **identitykit Manifest（M2 已推翻当时的结论）**：本会话曾判定 identitykit 是契约-only
  包、无需补 Manifest；ROADMAP M2 任务 1 要求它注册成工具，已按其执行新增三个工具
  （详见「M2 四条任务」）。sessionkit 仍是契约-only 包（工具入口在 shellkit），这条不变。
- [x] **覆盖率**：`httpkit` 90.3%、`adapters/httpx` 92.1%（均 ≥ 50%，ROADMAP 目标已达成）。
  全模块 `go test -cover ./...` 除 cloudkit 外每个 kit 均非零覆盖（详见 commit 内覆盖日志）。
- [x] **修复 Go 1.25 toolchain 缺 `covdata`**：根因——`go.mod` 要求 go≥1.25，`GOTOOLCHAIN=auto`
  选中模块缓存里的 `v0.0.1-go1.25.0.linux-amd64`，该分发**未带 `covdata` 预编译二进制**，
  且 GOROOT 只读导致 Go 无法按需就地构建，于是 `go test -cover ./...` 报
  `go: no such tool "covdata"`。修复：从 toolchain 自带源码构建 `covdata` 落回其 tool 目录，
  并加 `scripts/repair-covdata.sh`（幂等、非致命），在 `verify.sh` 里自动自愈。
  **验证**：多包 `go test -cover ./...` 退出码 0、零 `covdata` 报错、所有 kit 覆盖率非零。

### TODO（按优先级）

- [ ] **四家云真实凭据验证**（M1 唯一未达标项，外部凭据阻塞）：在具备真实 AK/SK 的机器上，
  对 AWS / 阿里云 / 腾讯云 / 华为云各跑通一次 `cloud_ak_verify` 与 `cloud_asset_list`。
  本机 `CAPKIT_CLOUD_*` 数量为 0；离线假件测试不等价真实调用，未验证就不写已验证。
- [x] `docs/STATUS.md` 补 cloudkit 段（云能力清单、只读边界、华为云诚实缺口、AK 脱敏）
  ——已随 d787cc0 提交，`docs/STATUS.md` 与 README 均含「四家云未用真实凭据跑过」
- [ ] **memshell 投递工具化**（M2-4 未纳入，见偏离记录第 5 条）：`memshell` 的
  `DeployPlan`/`Deployer` 仍未注册成工具。它是内存马路径，前提是已有一个 webshell 会话
  （`DeployPlan.Session`），更适合随 M4（容器逃逸执行）一起做。
- [ ] v2 扩展七项（云控制台接管、容器逃逸执行、跳板机深度采集、隧道自动搭建、反序列化验证、AD 域利用、C2 接入），详见文档第十章

> 红线 4 的白名单机制（2026-10-19 复核）：`scripts/check-imports.sh` 原有两关
> （kit/host 边界、copyleft 名单）之外，已新增 `scripts/sdk-allowlist.txt` 作为第三方
> 模块白名单——格式 `<kit> <module-root>`，按 kit 分别授权，capkit 根包仍限定标准库。
> 四家云 SDK 已在该白名单登记（`kits/cloudkit github.com/aws/aws-sdk-go-v2` 等），
> 并在 `DEPENDENCIES.md` 有对应条目，红线 4 两个落点均已满足。

## 四、红线

1. kit 之间禁止互相 import，组合只在 `all/`
2. 不改 `gates/` 的 scope→approval→ratelimit→audit 顺序与语义
3. 不实现平台侧认证（用户登录、RBAC 归宿主）
4. 新依赖必须写进 `DEPENDENCIES.md` 并更新 `check-imports.sh` 白名单
5. 禁止 import GPL/AGPL 项目代码（sliver、sqlmap、jwt_tool、hakrawler、Arjun），只能 subprocess
6. 能用官方 SDK 解决的能力不要手搓（云签名、分页、重试一律交给 SDK）
7. 凭据、临时登录 URL 禁止明文进日志与证据库

## 五、常用命令

```bash
export PATH=/home/c1ay/.local/go/bin:$PATH   # go 不在默认 PATH

go build ./... && go vet ./... && go test ./...
go test -run TestContractEnvelope -v .        # 看每个工具的契约结果
CAPKIT_CONTRACT_FILTER=httpkit go test -run TestContractEnvelope -v .   # 只测某组
bash scripts/check-imports.sh                 # 依赖与 import 边界
bash scripts/verify.sh                        # 一键全验收
```
