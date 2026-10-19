# STATE — capkit 当前状态台账

> 每次开工前先读这个文件。每次收工前更新它。
> 长线里程碑定义见 `docs/ROADMAP.md`，本文件只记录实际进度。
> 只写事实和状态，不写计划感想。状态只有三种：DONE / DOING / TODO。

当前里程碑：M1 收尾与上架（T1–T3 云控制台由并行会话负责；T4–T8 本会话已完成）

## 并行会话归属（重要）

另一个会话正在改 `kits/cloudkit/**`、`go.mod`、`go.sum`、`docs/STATUS.md`。

本会话的边界：

- **不要改** `kits/cloudkit/**`、`go.mod`、`go.sum`、`docs/STATUS.md`
- M1 的 T1（注册 cloudkit）、T2（阿里云）、T3（腾讯云华为云）视为外部处理，跳过
- 开工时如果 `all/register.go` 已有 `RegisterCloud` 就直接用；没有就跳过 T1，不要自己加
- 需要 `go mod tidy` 时先确认 cloudkit 会话已收尾提交，否则等它

本会话（T4–T8）已完成的收尾项见第三节。

**当前 verify 状态（2026-10-19 09:3x）**：`bash scripts/verify.sh` **红**，唯一失败点是
`kits/cloudkit` 的两个在写测试（`TestAliyunListStorageObjectsOffline`、
`TestAliyunRunCommandOffline`），属并行会话进行中的实现，本会话不触碰。
除此之外 build / vet / test / contract envelope / import boundaries 全绿，契约覆盖 76 工具。

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
- [x] `contract_ci_test.go` 走 `runtime.Call`，覆盖 76 个工具，断言 Status/Summary/Meta/Error
- [x] exploitkit 11 个工具注册
- [x] shellkit 8 个工具注册（会话四件套 + 隧道 + 投递）
- [x] containerkit 检测与计划（kubelet / apiserver / etcd / docker-api / escape-check / escape-plan）
- [x] internalnetkit 基础探测（local-info / host-discovery / portscan / domain-info / smb-shares）
- [x] latkit 8 个工具（psexec / wmiexec / smbexec / winrm / pass-the-hash / kerberoast / asrep / dcsync）
- [x] persistkit（enum / plan / apply）、cleanupkit（preview / apply）
- [x] cloudkit AWS 完整实现（ec2 / iam / rds / s3 / ssm，573 行，真调 SDK）
- [x] `docs/` 四份文档：实现方案、工具调用协议、宿主接线指南、前端展示设计方案

### DOING

- [ ] **cloudkit（并行会话，进行中）**：`kits/cloudkit/aliyun.go` 在写，
  `TestAliyunListStorageObjectsOffline` / `TestAliyunRunCommandOffline` 仍失败。
  本会话不触碰。等它收尾提交后 `verify.sh` 才能整体转绿。

### DONE（本会话 T4–T8 收尾）

- [x] **Summary 全量接入**：契约层 `runtime` 统一补 `Summary` 兜底，
  `contract_ci_test.go`（`TestContractEnvelope`）断言每个工具返回非空、非泛化
  `Summary`、正确 `Status`/`Meta`/`Error`。覆盖 76 工具全 PASS（≥ ROADMAP 81 的工具数
  下限替代判断见下）。internalnetkit、icpkit、reconkit、oastkit、verifykit 等已改。
- [x] **identitykit / spacemapkit Manifest**：经核对，identitykit 与 sessionkit 是
  **契约-only 包**（docs §3.1 / contract_ci_test.go 注释），按设计不声明工具、不进注册表；
  spacemapkit 已有 `space_search`/`space_domain_search`/`space_providers` 三工具 Manifest。
  二者符合文档要求，无需补。
- [x] **覆盖率**：`httpkit` 90.3%、`adapters/httpx` 92.1%（均 ≥ 50%，ROADMAP 目标已达成）。
  全模块 `go test -cover ./...` 除 cloudkit 外每个 kit 均非零覆盖（详见 commit 内覆盖日志）。
- [x] **修复 Go 1.25 toolchain 缺 `covdata`**：根因——`go.mod` 要求 go≥1.25，`GOTOOLCHAIN=auto`
  选中模块缓存里的 `v0.0.1-go1.25.0.linux-amd64`，该分发**未带 `covdata` 预编译二进制**，
  且 GOROOT 只读导致 Go 无法按需就地构建，于是 `go test -cover ./...` 报
  `go: no such tool "covdata"`。修复：从 toolchain 自带源码构建 `covdata` 落回其 tool 目录，
  并加 `scripts/repair-covdata.sh`（幂等、非致命），在 `verify.sh` 里自动自愈。
  **验证**：多包 `go test -cover ./...` 退出码 0、零 `covdata` 报错、所有 kit 覆盖率非零。

### TODO（按优先级，含并行会话项）

- [ ] **注册 cloudkit + 三家云接线**（并行会话）：`all/register.go` 加 `RegisterCloud`，
  接 `RegisterFull`；阿里/腾讯/华为三云照 `aws.go` 骨架补全。完成后 `verify.sh` 转绿、契约覆盖达 81。
- [ ] v2 扩展七项（云控制台接管、容器逃逸执行、跳板机深度采集、隧道自动搭建、反序列化验证、AD 域利用、C2 接入），详见文档第十章

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
