# ROADMAP — capkit 长线实施计划

> 本文件是执行序，能力定义见 `docs/究极渗透能力包实现方案.md`。
> 每次只做一个里程碑。Exit 条件不满足，不许进下一个。

## 总原则

- 一次一个里程碑，禁止并行开两个
- 每个里程碑独立提交，提交前 `bash scripts/verify.sh` 必须 PASS
- 完成一个里程碑后更新 `STATE.md`，把状态从 DOING 改 DONE，把下一个改 DOING
- Exit 条件里带"真实环境"的，必须真的跑通，不接受"逻辑上应该可以"

## 章节映射（每个里程碑开工前必读）

能力定义、契约、开源选型全部在 `docs/究极渗透能力包实现方案.md`。本文件只给执行序和验收，不给实现细节。开工前按下表读对应章节，不要凭本文件的概述去实现。

| 里程碑 | 必读章节 | 读它解决什么 |
|---|---|---|
| M1 收尾与上架 | 第四章（4.1–4.12 能力矩阵）、第六章（开源选型与许可证）、第八章（验收标准） | 每个能力该用什么开源项目、哪些 GPL 只能 subprocess、验收具体指标 |
| M2 会话与身份 | 第五章 5.1 Session、5.2 Identity、5.5 工具输出契约 | 窄接口设计、可选能力探测、信封字段要求 |
| M3 云控制台接管 | 第十章 10.1 | 四家云的联合身份换取方式与控制台入口 |
| M4 容器逃逸执行 | 第十章 10.2、第四章 4.9 | 四条逃逸路径、回滚要求、k8s/docker 检测面 |
| M5 跳板机与隧道 | 第十章 10.3、10.4 | 五块采集内容、杀软映射表、隧道选型规则 |
| M6 反序列化验证 | 第十章 10.5 | 生成、投递位置、三层判定 |
| M7 AD 域利用 | 第十章 10.6 | 五个工具的攻击面与依赖 |
| M8 C2 接入 | 第十章 10.7 | Sliver 走 gRPC 不许 import、msf 走 RPC |
| M9 免杀与投递 | 第四章 4.11、4.12 | 免杀自检边界、投递分块要求 |
| 所有里程碑 | 第五章 5.5 工具输出契约、第九章 风险 | 新工具的 `Summary`/`Status`/`Meta`/证据要求，以及许可证与能力失控风险 |

合同类代码（`Result`、`Target`、`ToolSpec`、`Port`）改动前必须先读第五章，不得自行改字段语义。

---

## M1 收尾与上架（预计 1 周）

**Enter**：无，直接开始

**任务**

1. `all/register.go` 增加 `RegisterCloud`，接进 `RegisterFull`
2. `aliyun.go` 用 alibabacloud-go 接线（sts 验证、ecs 实例、ram 用户策略、oss 桶、ecs RunCommand）
3. `tencent.go` 用 tencentcloud-sdk-go 的 cvm/cam 接线
4. `huawei.go` 用 huaweicloud-sdk-go-v3 的 ecs/iam 接线
5. 未接 Summary 的 kit 全部补齐
6. `identitykit`、`spacemapkit` 补 Manifest
7. `httpkit` 与 `adapters/httpx` 覆盖率提到 50%
8. 修 `covdata` 缺失，让 `go test -cover` 可用

**Exit**

- 契约测试覆盖 ≥ 81 个工具，全 PASS
- 四家云的 `cloud_ak_verify` 与 `cloud_asset_list` 用真实凭据各跑通一次
- `go test -cover ./...` 正常输出，无 0% 的 kit
- `verify.sh` 全绿

---

## M2 会话与身份闭环（预计 1 周）

**Enter**：M1 完成

**任务**

1. `identitykit` 注册成工具：Cookie 罐、CSRF 提取回填、Token 刷新判定
2. `AuthFlow` 契约落地，宿主可注册站点级登录脚本
3. `shellkit` 的 WebShell 会话接入 `sessionkit.Session`
4. 打通「漏洞 → WebShell 落地 → 会话接管」链路

**Exit**

- 在一个真实靶机上，从 `cmdi_probe` 命中 → `cmdi_execute` → 落 WebShell → `session_open` → `session_exec` 跑通 `id`
- 带登录态的目标上，`Identity.Headers()` 能自动注入 Cookie
- `verify.sh` 全绿

---

## M3 云控制台接管（预计 3 天）

**Enter**：M1 完成（依赖 cloudkit）

**任务**

1. `cloud_console_login` 四家云：联合身份换临时凭证，再换控制台登录 URL
2. 登录 URL 经 `sealer` 加密存储，`Summary` 只报账号与有效期
3. 过期自动重换，不做本地缓存

**Exit**

- 阿里云与 AWS 各换出一次可用登录 URL，浏览器打开能进控制台
- 证据库里搜不到明文凭据
- `verify.sh` 全绿

---

## M4 容器逃逸执行（预计 1 周）

**Enter**：M2 完成（需要会话）

**任务**

1. `container_escape_exec` 按 plan 执行单条路径
2. 四条路径：docker.sock、privileged（release_agent/core_pattern）、hostPath、k8s privileged pod
3. 每条路径强制 `rollback` 字段

**Exit**

- docker.sock 与 privileged 两条在靶场跑通，能执行命令并读到宿主文件
- 执行完 `rollback` 能还原，宿主无残留
- `verify.sh` 全绿

---

## M5 跳板机收集与隧道自动化（预计 1 周）

**Enter**：M2 完成

**任务**

1. `inet_host_profile`：系统、杀软、网络、敏感文件、凭据线索五块
2. 杀软与 EDR 识别：进程、服务、驱动、注册表，映射到产品（360、火绒、Defender、卡巴、CrowdStrike、Sangfor、天擎、Symantec、McAfee、趋势），推断版本与检测面。完整清单见究极文档 4.12。只识别，不做对抗，不含 AMSI/ETW/BYOVD/免杀载荷
3. `tunnel_auto`：探测出网方式 → 选型 → 部署 → 验证 → 返回清理命令

**Exit**

- 在 Linux 与 Windows 跳板机上各采集一份完整 profile
- 两种网络环境（可直出、仅 HTTP 代理）都能自动建起隧道并返回可用 socks
- `verify.sh` 全绿

---

## M6 反序列化验证（预计 4 天）

**Enter**：M2 完成

**任务**

1. `deser_verify`：生成（复用 deser_generate）→ 投递（body/header/cookie/base64）→ 判定（回显/OAST/时间）
2. 支持 Java（ysoserial）与 PHP（phpggc）

**Exit**

- Java 反序列化靶标上命中一条 gadget 链，判定依据可复现
- PHP 靶标上命中一条
- `verify.sh` 全绿

---

## M7 AD 域利用（预计 2 周）

**Enter**：M2、M5 完成

**任务**

1. `ad_adcs_attack`：ESC1 至 ESC8
2. `ad_ticket`：Golden、Silver、S4U2Self、S4U2Proxy
3. `ad_delegation`：非约束、约束、RBCD
4. `ad_acl_abuse`：GenericAll、WriteDACL、ForceChangePassword、AddMember
5. `ad_bloodhound_collect`：SharpHound 采集加最短路径分析

**Exit**

- 域环境（1 DC + 2 成员机）上，从普通域用户拿到域管
- 至少两条路径可复现：ADCS 或 ACL 滥用
- `verify.sh` 全绿

---

## M8 C2 接入（预计 1 周）

**Enter**：M2 完成

**任务**

1. `sliver` adapter：gRPC 通信，禁止 import 其 Go 代码
2. `msf` adapter：RPC + msgpack
3. `session_open` 的 `kind` 增加 `sliver`、`msf`

**Exit**

- Sliver 上开出一个 session，`session_exec`、`session_upload`、`tunnel_open` 全可用
- 上层调用代码零改动，只换 kind
- `verify.sh` 全绿

---

## M9 载荷投递（预计 3 天）

不含免杀。只做投递通道与完整性校验。杀软与 EDR 只做识别（见究极文档 4.12），明确不做对抗。

**Enter**：M8 完成

**任务**

1. 接入 4zreco 的 `deliver`：分块投递，逐块 sha256，乱序发送，清单不落目标盘
2. 投递方式：HTTP 分块、WebShell 上传、SMB 写入
3. 目标侧重组命令与校验，投递完成后按配置清理落盘件

**Exit**

- 分块投递在两端能还原，sha256 一致
- 投递件不落目标盘，或落盘后自动删除
- 返回可执行的清理命令，与 `cleanupkit` 打通
- `verify.sh` 全绿

---

## 顺序约束

M1 → M2 →（M3 / M4 / M5 / M6 / M8 可并行，但一次只做一个）→ M7 → M9

M3 依赖 M1，M4、M5、M6、M8 依赖 M2，M7 依赖 M2 与 M5。
