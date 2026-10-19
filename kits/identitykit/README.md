# identitykit

契约包，无工具。

本包实现 target-side 的 identity 契约（docs §5.2）：把「登录后如何维持一个身份」
拆成可复用的积木，供宿主在自己站点专属的登录流程里组装，最终产出
`capkit.Identity`，喂给带门禁的 `HTTPDoer`。

## 提供什么

- `JarIdentity`：cookie jar 形态的身份，`NewJarIdentity` 建立、`SetCookies` /
  `AddCookie` 注入、`Headers` 输出
- `TokenIdentity`：bearer/token 形态的身份，可带 `Refresh` 回调，`Headers`
  在需要时按 token 快照刷新
- `FormFlow`：表单/JSON 登录流程的 `capkit.LoginFlow` 实现，`Login` 走
  `capkit.Credentials` 返回一个 `Identity`
- `ExtractCSRF` / `ExtractCSRFNamed`：从 HTML hidden input / meta 标签里抽
  CSRF token 的纯函数，`CSRFNames` 是默认识别的 token 名集合

## 给谁用

宿主 runtime：某个站点需要认证时，宿主用它实现站点专属的 `LoginFlow`，
把 `FormFlow` 与站点的登录参数、CSRF 抽取组合起来；`JarIdentity` /
`TokenIdentity` 则是 `Identity` 契约的两个现成实现。

## 为什么不注册工具

identitykit 是 **契约 + 原语库**，不是 agent 可调用的能力：它没有
`Manifest()`，没有 `ToolSpec`，也没有 `Call`。身份是宿主在装配期注入到
HTTP 链路里的策略对象，不是一个可以被 agent 单独调用的动作。把登录做成
工具会让 agent 绕过宿主的 scope/审批/凭据策略，因此这里刻意不注册任何工具。
