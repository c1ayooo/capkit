# capkit 项目工作流

本项目覆盖全局 Matt Pocock 工作流，以本文件为准。全局 skill 在 `~/.zcode/skills/`。

## 必须走的流程（不是建议）

每个任务按这个顺序，不许跳步：

1. **`/implement`**（或 `/implement-spec`，有规格文件时）—— 从任务描述实现
2. **`/tdd`** —— 在下方预定义 seam 上，垂直切片：一个测试 → 一个实现 → 跑一次 → 下一个
3. **`/code-review`** —— 改动完成后双轴自查（Standards + Spec）
4. `bash scripts/verify.sh` —— 必须 VERIFY PASSED

小改动可以不走完整流程，但"小改动"的定义是：单文件、不超过 50 行、不新增工具、不改契约。超出这个范围就必须走。

## 预定义 seam（tdd 直接在这些边界上测，不用再问）

| 范围 | 测试边界 |
|---|---|
| 任意 kit | `Capability.Call` 返回的 `Result` 信封 |
| 云能力 | `cloudkit.Provider` 接口：Verify / ListAssets / ListIAM / ListStorage / ListCommand |
| 会话能力 | `sessionkit.Session` 接口：Exec / Upload / Download / Tunnel / Close |
| 利用能力 | `exploitkit` 各 Probe 的 `Finding` 返回值 |
| 门禁 | `gates.Chain.Before/After` 的行为，含 scope 拒绝、限速、审批 |
| 工具发现 | `Registry.Specs()` 与 `Manifest.Tools` 的一致性 |

不测私有方法、不 mock 内部协作者、不用和生产代码相同的算法重算期望值。

## 开工与收工

- 开工第一步：读 `STATE.md` 与 `docs/ROADMAP.md`。当前在哪个里程碑、下一步做什么，只看这两个文件，不要凭上下文推断
- 开工前核实：用 `git log --oneline -5` 和 `bash scripts/verify.sh` 对照 `STATE.md`，状态与实际不符时先纠正台账，再干活
- 一次只做一个里程碑（`docs/ROADMAP.md` 里的 M1 至 M9），禁止并行开两个
- 收工最后一步：更新 `STATE.md`，跑 `verify.sh`，提交。会话可能随时中断，没写进台账的进度等于没做
- 描述状态只有两种：验收通过，或哪一项没过、为什么。禁止「基本完成」「主体已实现」

## 红线

1. kit 之间禁止互相 import，组合只在 `all/`
2. 不改 `gates/` 的 scope → approval → ratelimit → audit 顺序与语义
3. 不实现平台侧认证（用户登录、RBAC 归宿主）
4. 新依赖必须写进 `DEPENDENCIES.md` 并更新 `scripts/check-imports.sh` 白名单
5. 禁止 import GPL/AGPL 代码（sliver、sqlmap、jwt_tool、hakrawler、Arjun），只能 subprocess
6. 能用官方 SDK 的能力不许手搓（云签名、分页、重试交给 SDK）
7. 凭据与临时登录 URL 禁止明文进日志、Summary 或证据库

## 新增能力的四件套

每加一个工具必须同时产出：

1. `Manifest` 里的 `ToolSpec`，含 `input_schema` 与 `output_schema`
2. 注册进 `all/register.go`
3. 结构化 `Summary`：写「对什么目标做了什么 + 关键结果 + 数量」
4. 至少一个测试，跑在预定义 seam 上

缺任何一件，这个工具算没做完。

## 常用命令

```bash
export PATH=/home/c1ay/.local/go/bin:$PATH
go build ./... && go vet ./... && go test ./...
go test -run TestContractEnvelope -v .
CAPKIT_CONTRACT_FILTER=cloudkit go test -run TestContractEnvelope -v .
bash scripts/check-imports.sh
bash scripts/verify.sh
```
