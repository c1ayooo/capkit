# STATE — capkit 当前状态台账

> 每次开工前先读这个文件。每次收工前更新它。
> 长线里程碑定义见 `docs/ROADMAP.md`，本文件只记录实际进度。
> 只写事实和状态，不写计划感想。状态只有三种：DONE / DOING / TODO。

当前里程碑：**M2 会话与身份闭环 — 全部任务与 Exit 四项已实测通过，待本轮提交后置 DONE**

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
   （同 enterprisekit 的 resolver），`capkit.Deps` 装不下，因此由
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
- [ ] **M2：会话与身份闭环 — 四项任务与 Exit 四项已全部实测通过，待本轮提交 push 后置 DONE**。
  见本文件「M2 会话与身份闭环」一节（靶机 `capkit-lab:latest` @ `127.0.0.1:18080`，
  四项真实回显已逐条记录）。

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
