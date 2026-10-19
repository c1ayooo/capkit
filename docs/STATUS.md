# 状态与已知差距

本文档记录 capkit 已实现的内容、与规格的偏差、以及下一步。README 只保留能力清单与接线方式。

更新时间：2026-10-19

## 已实现

**内核**

• 契约、注册表、运行时、门禁（授权 / 审批 / 限速 / 审计 / 脱敏）
• 适配器：带门禁的 HTTP、带门禁的子进程执行器、AES-GCM 加密、内存版设置与审计
• `runtime/httpapi`：通用 `GET /tools`、`GET /manifests`、`POST /call`
• 契约定义：tool / result / output / target / evidence / event / settings / manifest / template / fingerprint / session / identity
• 面向 agent 的 `Result` 信封：六态 `Status`、有界 `Summary` 与 `Data`、`Findings`、`Next`、`Meta`（由运行时统计的请求预算）、幂等键
• `Planner` 接口
• 共享根包辅助函数：`FirstNonEmpty`、`TimeoutFromMS`、`Truncate`、`PreviewRunes`、`EvidenceRefs`、`PageWindow`（kit 只能 import 根包，所以辅助函数统一定义在根）
• 五个可运行示例：`minimal`、`verify-chain`、`session`、`webshell-chain`（cmdi → 落地 → 会话接管全链路）、`identity-login`（登录态自动注入 Cookie）
• `harness/` 假靶标，含假 nuclei

**信息收集类**

• `httpkit`：`http_probe`，以及 `kind: http` 的模板引擎
• `nucleikit`：`nuclei_scan`、`nuclei_status`，JSONL 解析，`kind: nuclei` 的模板引擎（每条模板写入临时文件）
• `templatekit`：引擎中立的模板模型、YAML/JSON 包加载、目录检索、校验、来源与校验和；不执行
• `fingerprintkit`：规则模型、匹配器、favicon mmh3、wappalyzer/webanalyze/dddd 同步、`Provider` 实现；不写资产图
• `verifykit`：`verify_plan` / `verify_execute`，只依赖 `FingerprintProvider` + `TemplateCatalog` + `TemplateEngine`
• `githubkit`：GitHub 代码搜索密钥 dork、带令牌与限速的客户端、密钥类型分类与静态可信度评分；走外部 `Fetcher` 端口，不走目标域 HTTP
• `reconkit`：引擎中立的子域 → 解析 → 端口 → HTTP 流水线，由宿主提供 provider 与 `AssetSink`；不写资产图
• `playbookkit`：确定性 HTTP/TCP/DNS 验证剧本，带断言、变量提取、硬性上限、confirmed/refuted/blocked 三态结论；预设剧本通过 `EmbeddedPresets()` 内嵌
• `toolparse`：httpx/ffuf/katana/nuclei/nmap/sqlmap/dalfox/arjun/fscan/hydra 等输出的结构化解析，产出字段与归一化事实候选
• `spacemapkit`：FOFA/ZoomEye/Quake/Shodan/Hunter 检索，按引擎归一化字段与行，域名字法查询；API key 走 resolver/env/settings，所有 HTTP 走 `Fetcher`
• `enterprisekit`：爱企查/天眼查/快查/风鸟四个 provider、工厂、企业搜索与详情能力、宿主存储支撑的 BFS 采集器
• `oastkit`：dnslog.cn 回连域名与记录，不需要自建 OAST
• `icpkit`：工信部 ICP 备案查询与类型说明

**利用类**

• `exploitkit`：有界的 cmdi/SSTI/LFI/SQLi/SSRF 探测，带基线差分；LFI 日志投毒验证；Redis gopher payload 构造；ysoserial/phpggc payload 生成；可选 msfconsole 执行器；不含内置目标，不做一键链

**凭据类**

• `credkit`：云 AK/SK、数据库、SSH 三类凭据的只读验证

**云**

• `cloudkit`：5 个云资产工具，覆盖阿里云 / 腾讯云 / AWS / 华为云
  - `cloud_ak_verify`（low）→ STS `GetCallerIdentity`，返回账号与身份类型
  - `cloud_asset_list`（medium）→ ECS/CVM/EC2 实例 + RDS/CDB 实例，接受 `cursor` 分页
  - `cloud_iam_list`（medium）→ 子用户、策略、AccessKey 元数据（不返回密钥本体），带边界的有界权限探测
  - `cloud_storage_list`（medium）→ 对象存储桶与对象元数据
  - `cloud_run_command`（**high**）→ 云助手执行命令，经 `gates` 的 approval；stdout 超 4KB 落证据，只回 `EvidenceRef`
  - 签名、分页、重试全部交官方 SDK（aws-sdk-go-v2 / alibabacloud-go / tencentcloud-sdk-go / huaweicloud-sdk-go-v3）；capkit 只做两件事：把 SDK 的 HTTP 客户端换成注入的 `HTTPDoer`，把 SDK 响应映射成 `Result` 信封
  - 只读优先：没有删除实例/对象、改 IAM 策略、创建 AccessKey、控制台接管的路径
  - 凭据只从入参读取，不落盘不写日志；AK 在 Summary 与错误信息里脱敏为前 4 位 + 后 4 位
  - 错误区分：凭据无效 / 权限不足 / 地域错误 / 实例不在运行态 / 不存在 / 超时 / 限流 / 不支持
  - 华为云能力**故意窄于**其余三家：`cloud_storage_list` 与 `cloud_run_command` 明确返回 `unsupported`（OBS 在独立的 `huaweicloud-sdk-go-obs`，未引入；ECS v2 无云助手 API），不用手搓签名伪造能力

**会话与后渗透**

• `sessionkit`：`Session`/`SessionManager` 契约，四种传输：
  - SSH（x/crypto/ssh：执行/上传/下载/隧道）
  - WinRM（WSMan SOAP 走 `HTTPDoer` 端口，所以每次调用都受授权、限速、审计约束）
  - SMB（通过 `ProcessRunner` 调 smbclient，密码走 `PASSWD` 环境变量而非命令行参数）
  - CLI（本地进程，走 `ProcessRunner`，有白名单）
• `identitykit`：目标侧身份——Cookie 罐、CSRF token 提取、OAuth/JWT 主动刷新，并注册三个工具（M2）：`identity_login`（按 kind 调宿主注册的 `AuthFlow`，出参 user/hosts/label）、`identity_csrf`（GET 页面抽 token，返回 name/token/source）、`identity_token_check`（吃 `TokenSnapshot`，返回 `needs_refresh` 与依据）。凭据只从入参读，不落盘、不明文进日志与证据；返回里的头部值脱敏（`Cookie: <N cookies>`、`Authorization: <redacted>`）
• `shellkit` 会话工具：`session_open/exec/upload/download`、`tunnel_open`、`session_list`、`session_close`，所有传输方式调用形状一致；`webshell_deploy`（M2，high）＝ `payload.Generate` 渲染 + 宿主 `WebShellDeployer` 落盘，出参落点 URL、可直接喂 `session_open` 的 webshell 参数、删除落盘件的清理命令
• `all.RegisterWebShellOpener(mgr, exec)`：一行把 WebShell 装配进 `sessionkit.Manager` 的 `kind=webshell`
• `privesckit`：只读的 Linux/Windows 提权枚举与候选排序（只识别与建议，不含 payload）
• `latkit`：impacket/NetExec/Kerberos 参数构造（psexec/wmiexec/smbexec、pass-the-hash、WinRM、Kerberoast/AS-REP/DCSync），只以子进程方式调用
• `persistkit`：Linux（cron/systemd/ssh-key/bashrc/ldpreload/pam）与 Windows（计划任务/服务/注册表 Run/WMI 订阅/COM 劫持）落点，分为 `persist_enum` / `persist_plan` / `persist_apply`，apply 需确认
• `cleanupkit`：痕迹清理分 `cleanup_preview` → `cleanup_apply`；apply 必须带 preview 的 `plan_id`，拒绝扩大范围，禁止无边界的一键清空
• `internalnetkit`：从立足点出发的宿主概览、存活发现、端口扫描、域信息、SMB 共享枚举，全部有界且走 `Session`
• `containerkit`：kubelet/apiserver/etcd/docker API 探测，加容器逃逸研判（只识别与排序，不含逃逸 payload）
• `avkit`：杀软与 EDR 识别指纹库（进程/驱动/服务/注册表/文件特征），只识别与决策，不含绕过产物
• `shellkit/listener`：Go 的 TCP 反弹 shell 监听、多会话注册表、命令执行、分块上传下载（无 C2 特性）

**其他端口与机制**

• `Fetcher` 端口：外部规则、情报、搜索下载，带限速与审计，不受项目目标域约束
• 长任务：任何工具输入可设 `"async": true`；运行时仍同步跑完门禁（授权被拒立刻返回，不是靠轮询），然后返回 `StatusPartial` 并在 `Data` 里给 `JobRef`。运行时自带的 `job_status` 工具负责轮询并最终返回该工具自己的信封
• 列表输出：可能超过 100 行的列表类工具接受 `cursor`，通过 `capkit.PageWindow` 返回 `Page{Total, Cursor, HasMore}`，让 agent 翻页而不是丢行
• `.github/workflows/ci.yml`：gofmt、测试、vet、覆盖率（无 kit 0%）、import 边界、五个示例实跑

## shellkit 子包（同一 module，需显式 import）

• `capkit/kits/shellkit`：`protocol`、`payload`、`memshell`（生成器 + 探测 + 宿主侧 Deployer）、`tunnel`（页面生成 + 宿主 Sink/PageDeployer）、`plan`（DeliverySink）、`session`（Executor）、`delivery` 状态机
• 4zrec 的 shell 流程通过 `delivery.Manager` 加数据库支撑的 `delivery.Store` 适配器接通，宿主适配器有端到端测试覆盖

## 可选子包（同一 module，仅放依赖较重的实现）

• `capkit/optional/pd`：subfinder/dnsx/naabu/katana 适配器
• `capkit/optional/nuclei-library`：进程内 nuclei 引擎

## 下一步

• 在具备真实 AK/SK 的机器上，对 AWS / 阿里云 / 腾讯云 / 华为云各跑通一次 `cloud_ak_verify` 与 `cloud_asset_list`（M1 唯一未达标项）
• `reconkit` 与模板包的宿主适配器
• WebShell 投递路径的大文件分块
• ProjectDiscovery 与 nuclei-library 的可选实现落地

## 已知与规格的差距

• **privesckit 只做识别与建议。** 规格 4.6 / P2.1 也提到利用，本模块停在枚举加候选排序，遵守规格自己在 4.12 / 9.2 划的界线（识别与决策进 capkit，成品载荷不进内核）。提权 payload 留在宿主侧或私有层
• **部分列表工具还没分页。** `inet_portscan` 与 `github_secret_search` 支持 `cursor`；其余列表类工具（dnslog 记录、测绘命中、dork 模板）当前返回有界集合，只置 `Truncated` 标记。`capkit.PageWindow` 是给任何超过 100 行的工具准备的辅助函数
• **`session_exec` 把截断后的 stdout 放在 `Data` 里。** 若严格执行“响应正文只进证据”的规则，agent 就看不到命令输出。折中方案：受运行时 8KB 上限约束，同时始终附带完整文本的 `EvidenceRef`
• **`Result.Text`、`EvidenceIDs` 与四个额外错误码**（`not_found`、`conflict`、`unavailable`、`need_human`）是对规格 5.5.1 / 5.5.3 的扩展。`need_human` 是六态 `Status` 必需的；其余保留是因为把它们合并成 `internal` 会误导 agent 去重试本不该重试的调用
• **四家云未用真实凭据跑过。** `cloudkit` 的四个厂商实现只经过离线假件测试（把 SDK 的 HTTP 客户端换成 `harness` 的 `HTTP`，断言签名头与请求形状），本机没有任何 `CAPKIT_CLOUD_*` 凭据，因此「真实 AK/SK 打真实云 API」这一步**未验证**。这不影响契约：离线测试覆盖工具形状、脱敏、错误分类与分页，但真机上的账号/权限差异（尤其是跨地域 endpoint 与主账号/子账号权限面）仍需一次实测
• **华为云能力窄于另外三家。** 见上文 `cloudkit` 段：`cloud_storage_list` 与 `cloud_run_command` 返回 `unsupported` 而非伪造实现
• **`sessionkit` 是契约-only 包。** 按设计不声明工具、不进注册表：它提供 `Session` 契约与四种传输，工具入口在 `shellkit`
• **`identitykit` 原为契约-only，M2 起改为带工具的包。** ROADMAP M2 任务 1 要求「identitykit 注册成工具」，以其为准，`identitykit/README.md` 原文「契约包，无工具」已同步改写。它仍不在 `RegisterFull` 里——flow registry 是宿主注入的协作者（同 `enterprisekit` 的 resolver），`capkit.Deps` 承载不了，宿主用 `all.RegisterIdentity(reg, flows)` 单独注册
• **四家云仍未用真实凭据跑过。** 见上文 `cloudkit` 段：本机 `CAPKIT_CLOUD_*` 数量为 0，真实 AK/SK 打真实云 API 这一步**未验证**；离线假件测试不等价于真实调用
• **WebShell 宿主 Executor 契约在 M2 收紧。** `session.ExecResult` 新增 `Encoding` 字段：文件读取只有宿主声明 `"base64"` 才解码，未声明一律原样（原先的嗅探会把 `abcdefgh` 这类纯文本解成垃圾字节）。未声明 base64 的宿主会从「被猜着解码」变成「原样返回」

## 注册粒度

`all.RegisterFull` 注册全部；`all.RegisterSession`、`all.RegisterPostExploitation`、`all.RegisterContainer`、`all.RegisterLateral` 是拆开的分组，给需要选择性注册的宿主用。

会话类 kit 声明 `sessions` 端口，latkit 声明 `process` 端口。宿主注册它们就必须提供 `capkit.SessionManager` / `capkit.ProcessRunner`，否则 `runtime.New` 会直接失败（fail closed），不会静默降级。

`reconkit`、`enterprisekit` 与 `identitykit` 不在 `RegisterFull` 里：它们需要 `capkit.Deps` 承载不了的宿主协作者（`AssetSink` / provider 集合、`ProviderResolver`、`AuthFlowRegistry`），所以宿主用 `RegisterRecon` / `RegisterEnterprise` / `RegisterIdentity` 单独注册。`webshell_deploy` 同理需要宿主 `WebShellDeployer`，走 `RegisterSessionWithDeployer`。
