# icpkit

工信部 ICP 备案查询客户端，Go 移植自 `ICP_Query`/`ymicp`（Rust 版）：
把 `beian.miit.gov.cn` 的 `icpproject_query` 网关整个逆向出来了——
鉴权、滑块验证码、查询、黑名单、App/小程序/快应用详情。

- 鉴权：`POST /api/auth`，表单 `authKey=md5("testtest"+timeStamp)&timeStamp=<ms>`，
  取 `params.bussiness` 作为 token
- 验证码：`getCheckImagePoint` 取图 → 缺口定位 → `checkImage` 换 `sign`
- 查询：`icpAbbreviateInfo/queryByCondition`
- 黑名单：`blackListDomain/queryByCondition`（域名）与
  `.../queryByCondition_appAndMini`（App/小程序/快应用）
- 详情：`icpAbbreviateInfo/queryDetailByAppAndMiniId`，App/小程序/快应用并发补齐

缺口定位是纯 Go 实现（`image/png` + 直方图 + 连通段扫描），无第三方图像依赖；
滑块验证失败时自动退化到兜底 sign（对应上游验证码关闭的场景）。
上游创宇盾拦截（`当前访问疑似黑客攻击`）会转成可读的 `unavailable` 错误。

Capability tools:

- `icp_query`：按域名/单位名称查备案或黑名单，`type` ∈ `web|app|mapp|kapp`，
  黑名单 `bweb|bapp|bmapp|bkapp`
- `icp_types`：列出支持的查询类型

Uses the external `Fetcher` port：请求有限速与审计，但不做项目目标范围检查
（MIIT 是数据源，不是被授权目标）。出口代理由宿主注入：

```go
kit := icpkit.New(capkit.Deps{Fetcher: fetch})
kit.Client().WithProxy("http://127.0.0.1:8888") // 可选
```

4zrec 接线见 `internal/platform/server/icp_tools.go`：`icp_query` /
`icp_types` 播种并绑定 recon/worker/planner/auto。它与 `icp_expand` 互补——
后者用备案号反查测绘引擎拿关联域名，本 kit 直读官方备案库。
