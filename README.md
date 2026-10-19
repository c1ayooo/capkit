# capkit

Go 语言的通用渗透能力内核库。宿主实现端口（授权、审批、证据、审计、存储、密钥），capkit 提供可复用的能力实现。

**它不是一个扫描器，也不是一个 agent 框架。** 它是契约层：让 Go 宿主挂载成套能力，不用每换一个项目就重写一遍工具。

> 仅限授权测试使用。每次工具调用都经过授权检查，未授权目标无法执行。

---

## 一、它能提供什么

### 1.1 四个核心机制

价值不只在工具数量，更在这四件事：

**① 门禁不可绕过**

每次调用固定走 `scope → approval → 限速 → 审计`。门禁在 `runtime.Call` 里，不在 kit 里，kit 作者没有能力跳过。`ScopeChecker` 要求 fail closed：目标无法解析或不在授权范围，直接拒绝，不猜测。

**② 统一结果信封**

所有工具返回同一个 `Result` 结构。agent 不需要为每个工具写一套解析逻辑，宿主不需要为每个工具写一套展示逻辑。

**③ 证据与结论分离**

`Data` 只放有界摘要；原始报文、命令输出、扫描日志走 `EvidenceSink` 存成证据，返回 `EvidenceRef`（ID、大小、sha256、200 字预览）。响应正文永远不会塞进 `Data`。

**④ 长任务、分页、幂等**

任何工具输入可设 `"async": true`，运行时同步跑完门禁（授权被拒立刻返回，不靠轮询），返回 `StatusPartial` 加 `JobRef`。列表类工具接受 `cursor`，返回 `Page{Total, Cursor, HasMore}`。同一幂等键重复调用不会重复执行副作用。

### 1.2 能力全景

24 个能力包，77 个工具。

**信息收集**

• `http_probe` — 带门禁的 HTTP 探测，返回状态、响应头、正文
• `recon_run` — 子域 → 解析 → 端口 → HTTP 的侦察流水线
• `space_search` / `space_domain_search` / `space_providers` — FOFA / ZoomEye / Quake / Shodan / Hunter 测绘检索
• `fingerprint_detect` — HTTP 指纹识别，匹配响应头、正文、Cookie、favicon
• `nuclei_scan` / `nuclei_status` — nuclei 执行与二进制状态
• `template_search` / `template_get` — 模板目录检索（只读，不执行）
• `tool_parse` / `tool_parse_list` — httpx/ffuf/nmap/sqlmap/katana 等 CLI 输出结构化解析
• `playbook_run` / `playbook_list` — 确定性剧本执行，断言失败即停
• `icp_query` / `icp_types` — 工信部 ICP 备案查询
• `enterprise_search` / `enterprise_detail` / `enterprise_providers` — 企业信息检索（爱企查/天眼查/快查/风鸟）
• `github_secret_search` / `github_dork_templates` — GitHub 代码搜索找泄露密钥

**漏洞验证与利用**

• `verify_plan` / `verify_execute` — 指纹 → 模板 → 执行的组合验证
• `cmdi_probe` / `cmdi_execute` — 命令注入探测与执行
• `ssti_probe` — 模板注入探测
• `lfi_probe` / `lfi_read` — 文件包含探测与读取，支持日志投毒
• `sqli_probe` — SQL 注入探测，带基线差分
• `ssrf_probe` — SSRF 探测
• `redis_gopher` — Redis gopher 协议 payload 构造
• `deser_generate` — ysoserial / phpggc 反序列化 payload 生成
• `msf_execute` — msfconsole 封装执行
• `oast_get_domain` / `oast_get_records` — dnslog.cn 回连域名与记录，验证盲打

**凭据**

• `credential_verify_cloud` — 云 AK/SK 最小化验证
• `credential_verify_db` — 数据库凭据只读验证
• `credential_verify_ssh` — SSH 凭据验证

**会话与通道**

• `session_open` / `session_exec` / `session_upload` / `session_download` / `session_list` / `session_close` — 统一会话契约，传输层可换（SSH / WinRM / SMB / CLI / WebShell）
• `tunnel_open` — 隧道建立

**后渗透**

• `privesc_advise` — Linux/Windows 提权枚举与候选排序
• `inet_local_info` / `inet_host_discovery` / `inet_portscan` / `inet_domain_info` / `inet_smb_shares` — 跳板机上的内网信息收集
• `lat_psexec` / `lat_wmiexec` / `lat_smbexec` / `lat_winrm` / `lat_pass_the_hash` / `lat_kerberoast` / `lat_asrep_roast` / `lat_dcsync` — 横向移动与域内攻击
• `persist_enum` / `persist_plan` / `persist_apply` — 权限维持，apply 需二次确认
• `cleanup_preview` / `cleanup_apply` — 痕迹清理，apply 必须带 preview 的 plan_id
• `container_escape_check` / `container_escape_plan` / `docker_api_probe` / `k8s_apiserver_probe` / `k8s_etcd_probe` / `k8s_kubelet_probe` — 容器与 k8s 探测、逃逸研判
• `av_detect` / `av_list` — 杀软与 EDR 识别（只识别，不做对抗）

**云**

• `cloud_ak_verify` — 云 AK/SK 验证，返回账号与身份类型，AK 脱敏
• `cloud_asset_list` — ECS/CVM/EC2 与 RDS/CDB 资产列举
• `cloud_iam_list` — 子用户、策略、AccessKey 元数据（不返回密钥）
• `cloud_run_command` — 通过云助手在实例上执行命令
• `cloud_storage_list` — 对象存储桶与对象元数据列举

### 1.3 一次调用发生什么

```
宿主调用 rt.Call(ctx, "cmdi_execute", input, callCtx)
  ├─ 0. 解析工具与输入，未知工具直接 not_found
  ├─ 1. scope        ExtractTargets 取出目标，ScopeChecker.Check 逐个校验
  ├─ 2. approval     Risk >= RequireApprovalAt 时调 Approver.Require
  ├─ 3. 限速         Limiter.Acquire(host, spec)，返回释放函数
  ├─ 4. 审计 start   AuditSink.Record
  ├─ 5. kit.Call     能力自己执行，外发只走 HTTPDoer / ProcessRunner 端口
  └─ 6. 审计 finish  AuditSink.Record，附证据 ID、耗时、状态
返回 Result{Status, Summary, Data, Findings, Evidence, Next, Meta.GateTrace}
```

任何一步拒绝，返回对应错误码，后续步骤不执行。`Meta.GateTrace` 记录实际走过的门禁与耗时。

### 1.4 宿主必须实现什么

15 个端口，按用途分组。注册不同 kit 需要不同子集。

**策略类（必备）**

• `ScopeChecker.Check(ctx, Target) error` — 授权边界，必须 fail closed
• `Approver.Require(ctx, ApprovalRequest) error` — 高风险工具的审批
• `Limiter.Acquire(ctx, key, spec) (release func(), error)` — 按主机限速
• `AuditSink.Record(ctx, AuditEvent)` — 审计事件，start 与 finish 两条

**通道类**

• `HTTPDoer.Do(ctx, Request) (*Response, error)` — kit 唯一允许的 HTTP 出口
• `Fetcher.Fetch(ctx, Request) (*Response, error)` — 外部规则/情报下载，不受目标范围约束
• `ProcessRunner.Run(ctx, ProcessSpec) (*ProcessResult, error)` — kit 唯一允许的子进程出口

**存储与密钥**

• `EvidenceSink.Record(ctx, Evidence) (id string, error)` — 证据归档
• `ArtifactStore.Put/Get/Delete` — 中间产物
• `Settings.GetString/GetBool/GetInt` — 配置
• `Sealer.Seal/Open` — 密钥加密存储
• `BinaryManager.Ensure/Update/Status` — 外部二进制（nuclei 等）

**基础**

• `Logger.Info/Warn/Error`
• `Clock.Now()`
• `IDGenerator.New(prefix) string`

会话类 kit 额外声明 `sessions` 端口（`SessionManager`），latkit 声明 `process` 端口。宿主没提供，`runtime.New` 直接失败，不会静默降级。

---

## 二、接入

### 2.1 最小接线

```go
reg := capkit.NewRegistry()
if err := all.RegisterHTTP(reg); err != nil { /* ... */ }

limiter := gates.NewLimiter()
audit := auditlog.NewMemory()
httpClient := httpx.New(myScope, limiter, audit)

rt, err := runtime.New(runtime.Config{
    Scope: myScope, Approval: myApproval, Limiter: limiter, Audit: audit,
    HTTP: httpClient, Settings: mySettings, Sealer: mySealer,
    RequireApprovalAt: capkit.RiskHigh,
}, reg)

res, err := rt.Call(ctx, "http_probe", input, capkit.CallContext{
    ProjectID: 1, Actor: "operator", TaskID: "t-001",
})
```

```bash
go run ./examples/minimal
```

### 2.2 注册粒度

```go
all.RegisterFull(reg)              // 全部 77 个工具
all.RegisterHTTP(reg)              // 只注册 httpkit
all.RegisterSession(reg)           // 会话类，需要 SessionManager
all.RegisterPostExploitation(reg)  // 后渗透
all.RegisterContainer(reg)         // 容器与 k8s
all.RegisterLateral(reg)           // 横向移动，需要 ProcessRunner
all.RegisterRecon(reg, sink, providers)   // reconkit 需要宿主注入协作者
all.RegisterEnterprise(reg, resolver)     // enterprisekit 同理
```

`reconkit` 与 `enterprisekit` 不在 `RegisterFull` 里，因为它们依赖无法用简单配置承载的宿主协作者。

### 2.3 HTTP 接口

```go
import "github.com/c1ayooo/capkit/runtime/httpapi"

http.ListenAndServe(":8080", httpapi.New(rt))
// GET  /tools      工具清单
// GET  /manifests  能力清单
// POST /call       {tool, input, context}
```

### 2.4 可运行示例

• `examples/minimal` — 最小接线，对本地 httptest 服务跑 `http_probe`
• `examples/verify-chain` — 指纹 → 模板 → 验证的完整链
• `examples/session` — 打开会话、执行命令、看信封

---

## 三、扩展

### 3.1 新增一个能力包（kit）

七步，缺一步就有坑。

**第 1 步：写能力说明**

一页纸：工具列表、每个工具的输入输出、风险等级、需要的端口、设置项、事件。这份说明决定后面所有代码的形状，先写清楚再动手。

**第 2 步：定义 Manifest**

```go
func (c *Capability) Manifest() capkit.Manifest {
    return capkit.Manifest{
        Name:       "mykit",
        Version:    "1.0.0",
        APIVersion: "v1",
        Requires:   []string{"http"}, // 声明依赖的端口，runtime 会校验
        Tools: []capkit.ToolSpec{
            {
                Name:        "my_probe",
                Description: "对目标做某某探测，返回状态与关键字段",
                InputSchema: json.RawMessage(`{
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"]
                }`),
                Risk:      capkit.RiskLow,
                RateLimit: capkit.RateLimitSpec{PerHostPerMinute: 60},
                ExtractTargets: func(in json.RawMessage) ([]capkit.Target, error) {
                    var v struct{ Target string `json:"target"` }
                    if err := json.Unmarshal(in, &v); err != nil {
                        return nil, err
                    }
                    return []capkit.Target{capkit.TargetFromString(v.Target)}, nil
                },
            },
        },
    }
}
```

**第 3 步：实现 Call**

```go
func (c *Capability) Call(ctx context.Context, call capkit.Call) (capkit.Result, error) {
    switch call.Tool {
    case "my_probe":
        var in struct{ Target string `json:"target"` }
        if err := json.Unmarshal(call.Input, &in); err != nil {
            return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
        }
        resp, err := c.http.Do(ctx, capkit.Request{Method: "GET", URL: "https://" + in.Target})
        if err != nil {
            return capkit.FailResult(capkit.Unavailable(err.Error())), nil
        }
        id, _ := c.evidence.Record(ctx, capkit.Evidence{
            Kind:     "http_exchange",
            Target:   capkit.TargetFromString(in.Target),
            Response: resp.Body,
            CreatedAt: time.Now(),
        })
        return capkit.Result{
            OK:     true,
            Status: capkit.StatusSuccess,
            Summary: capkit.ClampSummary(fmt.Sprintf("对 %s 探测，HTTP %d，%d 字节",
                in.Target, resp.Status, len(resp.Body))),
            Data:     mustJSON(map[string]any{"status": resp.Status}),
            Evidence: []capkit.EvidenceRef{capkit.NewEvidenceRef(id, "http_exchange", resp.Body)},
        }, nil
    }
    return capkit.FailResult(capkit.NotFound(call.Tool)), nil
}
```

**第 4 步：只用注入的端口**

禁止 `http.Get`、禁止 `exec.Command`、禁止自己读环境变量取密钥。凡是外发动作必须走 `HTTPDoer` 或 `ProcessRunner`，否则绕过门禁，宿主无法审计。

**第 5 步：加假靶标**

在 `harness/` 加假实现（假 HTTP 服务、假 nuclei、假进程），让测试不依赖网络和外部二进制。

**第 6 步：写契约测试**

至少三类：成功路径返回正确 `Status`、门禁拒绝返回 `blocked`、输入非法返回 `bad_input`。另外 `contract_ci_test.go` 会统一校验所有工具的 `Summary` 非空、`Meta.Tool` 正确、`Status` 属于六态。

**第 7 步：注册并登记依赖**

在 `all/` 加 `RegisterMyKit`，或由宿主直接 import。新增任何依赖，同一次改动里写进 `DEPENDENCIES.md`，否则 `check-imports.sh` 会拦。

### 3.2 新增一个工具到已有 kit

三处改动：`Manifest()` 的 `Tools` 加一条、`Call()` 的 `switch` 加一个分支、补测试。

三条硬要求：

• 作用于目标的工具**必须**实现 `ExtractTargets`，否则授权检查拿不到目标，等于放行
• `Summary` 必须说清做了什么，禁止「完成」「成功」「OK」
• 返回列表可能超过 100 条的，必须接受 `cursor` 并返回 `Page`

### 3.3 新增一种会话传输

实现 `sessionkit` 的窄接口：

```go
type Session interface {
    Exec(ctx context.Context, cmd string, timeout time.Duration) (*ExecResult, error)
    Info() SessionInfo
    Close() error
}

// 可选能力，用类型断言探测，没有就降级
type Uploader   interface{ Upload(ctx context.Context, remotePath string, data []byte) error }
type Downloader interface{ Download(ctx context.Context, remotePath string) ([]byte, error) }
type Tunneler   interface{ Tunnel(ctx context.Context, spec TunnelSpec) (Tunnel, error) }
```

新增一个 C2 或协议只换这个 adapter，上层 `session_open` / `session_exec` 不变。找不到可选能力时用 base64 或 socat 兜底，不要为此改契约。

### 3.4 新增一个适配器

实现 `port.go` 里对应的接口，放在 `adapters/` 下。两类必须注意：

• 带门禁的 HTTP / 子进程适配器：内部要真正调用 `ScopeChecker`、`Limiter`、`AuditSink`，不能只是转发
• 存储类适配器：`memstore` 是参考实现，Postgres 是可选实现。契约测试只跑内存实现，新存储适配器要自己补集成测试

### 3.5 包装一个外部 CLI 工具

GPL/AGPL 的工具只能这样接，不能 import 代码：

```go
res, err := c.proc.Run(ctx, capkit.ProcessSpec{
    Path:    "nmap",
    Args:    []string{"-sV", "-p", ports, host},
    Timeout: 5 * time.Minute,
    Targets: []capkit.Target{capkit.TargetFromString(host)},
})
```

密码类参数走 `Env`（如 `PASSWD`），不放 `Args`，否则会出现在进程列表和审计日志里。

---

## 四、约束

这一节是红线。违反任何一条，评审不通过。

### 4.1 分层与依赖

• 契约（`Capability`、`Result`、`ToolSpec`、`Port`）只在模块根，kit 不得重新定义
• kit 之间**禁止**互相 import，组合只发生在 `all/`
• `registry` 只做静态声明，不得持有实例；`runtime` 不得新增 `Register`
• kit 不得 import 宿主的任何包，不得出现具体项目名
• 新增依赖必须同时改 `DEPENDENCIES.md` 与 `scripts/check-imports.sh` 白名单

### 4.2 门禁

• 顺序固定 `scope → approval → 限速 → 审计`，不得调整
• `ScopeChecker` 必须 fail closed，解析失败视为拒绝
• 高风险工具（`RiskHigh` 及以上）必须过 `Approver`，默认阈值 `RequireApprovalAt = RiskHigh`
• 宿主没提供必需端口时 `runtime.New` 必须失败，不得静默降级

### 4.3 结果信封

• `Status` 只能是六种：`success` / `partial` / `failed` / `blocked` / `need_human` / `unavailable`
• `Summary` ≤ 200 字符，必须说清「对什么目标做了什么 + 关键结果」
• `Data` ≤ 8KB，超出走证据
• `OK` 由 `Status` 推导，不单独决策
• 响应正文、完整命令输出不得内联在 `Data`，一律进 `EvidenceRef`

### 4.4 错误码

只能用这十个：

`bad_input` / `scope_denied` / `approval_required` / `not_found` / `conflict` / `rate_limited` / `unavailable` / `internal` / `need_human` / `timeout`

不要新增，也不要合并。把 `unavailable` 合并成 `internal` 会误导调用方去重试本不该重试的操作。

### 4.5 证据与脱敏

• 凭据、AK/SK、Token、临时登录 URL 禁止出现在 `Summary`、`Data`、日志、提交信息
• 云 AK 在输出中必须脱敏，只保留前 4 位与后 4 位
• 证据必须带 `sha256` 与预览，预览 ≤ 200 字符
• 证据存储在宿主侧，capkit 只返回引用

### 4.6 危险操作

• 破坏性动作必须拆成 `preview` → `apply`，`apply` 必须带 `preview` 返回的 `plan_id`
• `apply` 必须校验范围没有扩大，拒绝执行超出 preview 声明的目标
• 禁止无边界选择器（一键清空、通配删除）
• 权限维持、命令执行、凭据使用类工具必须标 `RiskHigh` 或以上

### 4.7 许可证

• Apache-2.0 内核不得 import GPL / AGPL 代码
• `sliver`(GPL-3.0)、`sqlmap`(GPL-2.0)、`jwt_tool`(GPL-3.0)、`hakrawler`(GPL-3.0)、`Arjun`(AGPL-3.0) 只能以子进程调用
• 新引入的开源项目，先看许可证再决定怎么接

### 4.8 测试

• 每个工具至少三个测试：成功、门禁拒绝、非法输入
• 契约测试必须走 `runtime.Call`，不能直接调 `Capability.Call`，否则拿不到 `Meta.Tool` 兜底
• 新增 kit 覆盖率不低于 50%
• 测试不得依赖网络、真实凭据、外部二进制；用 `harness/` 的假件

### 4.9 文档与提交

• 新能力必须有一页说明，写清输入输出、风险、依赖端口
• 变更 `Result`、`ToolSpec`、`Port` 字段前先读规格第 5.5 节，不得自行改语义
• 提交信息写清改了什么能力，不写「优化」「修复」这种无信息量的词

---

## 五、验收

```bash
bash scripts/verify.sh        # 构建 + vet + 测试 + 契约 + import 边界
go test ./...
./scripts/check-imports.sh
```

`verify.sh` 全部通过才算完成。`check-imports.sh` 强制 kit 边界与依赖白名单。

## 六、目录

```
capkit.go / port.go / manifest.go / registry.go   根包契约
gates/        授权、审批、按主机限速、审计链
runtime/      从注册表构建能力，调用经过门禁
adapters/     httpx（带门禁的 HTTP）、exec、sealer
kits/         24 个能力包
optional/     重型实现（pd、nuclei-library），核心不 import
all/          注册入口
harness/      契约测试用的假靶标
contracts/    跨边界 JSON Schema
examples/     minimal / verify-chain / session
```

## 七、文档

• [宿主接线指南](docs/宿主接线指南.md) — 端口清单、注册粒度、门禁与运行参数、接线自检、常见错误
• [工具调用协议](docs/工具调用协议.md) — 发现 schema、调用、信封逐字段读法、六态决策表、错误码、幂等、证据、分页、异步轮询
• [究极渗透能力包实现方案](docs/究极渗透能力包实现方案.md) — 规格来源：kit 划分、输出契约、验收标准
• [实施路线](docs/ROADMAP.md) — M1 到 M9 里程碑与验收
• [状态与已知差距](docs/STATUS.md) — 已实现清单、与规格的偏差、下一步

接线最短路径：`宿主接线指南` 第 0 节一分钟版 → 第 1 节对齐端口 → `工具调用协议` 第 2 至 4 节确认调用形状。

## 八、许可证

Apache-2.0。见 `LICENSE` 与 `DEPENDENCIES.md`。

单个 Go module，没有独立的私有子模块。`kits/shellkit` 仅限授权使用，依赖宿主提供投递与执行通道。
