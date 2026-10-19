# identitykit

目标侧身份（docs §5.2）：把「登录后如何维持一个身份」拆成可复用的积木，并把
其中三个动作注册成 agent 可调用的工具。

## 提供什么

**原语（纯函数/类型，无 I/O 契约）**

- `JarIdentity`：cookie jar 形态的身份，`NewJarIdentity` 建立、`SetCookies` /
  `AddCookie` 注入、`Headers` 输出
- `TokenIdentity`：bearer/token 形态的身份，可带 `Refresh` 回调，`Headers`
  在需要时按 token 快照刷新
- `FormFlow`：表单登录流程的 `capkit.AuthFlow` 实现
- `ExtractCSRF` / `ExtractCSRFNamed` / `ExtractCSRFWithSource`：从 HTML hidden
  input / meta 标签抽 CSRF token，`CSRFNames` 是默认识别的 token 名集合

**宿主装配（M2）**

- `AuthFlowRegistry`：按 kind（`form`/`json`/`oauth`/`cas`/`bearer`）注册与查找
  站点级登录流程。`RegisterSite(kind, fn)` 一行装配；`RegisterFormSite(FormFlow)`
  一行装配表单登录。一个 kind 一条流程，重复注册报错而不是静默覆盖——
  覆盖会把凭据发到错误的站点。同一 kind 多站点时，注册一条按
  `Credentials.Fields["target"]` 分派的流程即可（`identity_login` 会把 target 填进去）。

**工具（agent 可调用，进注册表）**

- `identity_login`（high）：按 kind 调用宿主注册的 `AuthFlow` 完成登录。入参
  `target/kind/username/password/token/cookies/fields`，出参身份的
  `user/hosts/label`。凭据只从入参读，不落盘、不明文进日志与证据；返回里的
  头部值经过脱敏（`Cookie: <3 cookies>` / `Authorization: <redacted>`）。
- `identity_csrf`（low）：GET 单个页面并抽取 CSRF token，返回
  `name/token/source`（`hidden_input` 或 `meta`），可直接填进登录表单。
- `identity_token_check`（low）：吃 `TokenSnapshot`（`access_token`/`expires_at`/
  `issued_at`/`skew_ms`），返回 `needs_refresh` 与判断依据（剩余寿命对比安全余量）。
  `expires_at` 为空视为「无过期信息」，单独不触发刷新；token 本体不出现在返回里。

## 给谁用

宿主 runtime：在 `AuthFlowRegistry` 上注册站点登录，把注册表交给
`all.RegisterIdentity(reg, flows)`。之后 agent 用 `identity_login` 按 kind 登录，
宿主拿到 `Identity` 后注入到自己的 HTTP 链路。

## 为什么只有三个工具

身份体系里「维持一个身份」是可复用原语，「登录一个站点」才是 agent 的动作。
前者保持为库（宿主在装配期组合），后者注册成工具。把 `JarIdentity` 本身做成
工具没有意义——它没有可执行的动作，只是宿主 HTTP 链路的策略对象。

`Manifest.Requires` 声明 `http`：`identity_csrf` 需要一个带门禁的 `HTTPDoer`。
