# sessionkit

契约包，无工具。

本包实现 capkit 的 Session 契约（docs §5.1）及其 opener：一个新的传输只需
实现 `core.Session` 的三个方法（`Exec` / `Info` / `Close`，可选
`Upload` / `Download` / `Tunnel`），下游所有 kit（privesc、lat、persist、
cleanup、internalnet、container）就能不改代码地跑在它上面。

## 提供什么

- `Manager`：默认的 `core.SessionManager`，按 kind 注册
  `core.SessionOpener`（`ssh` / `winrm` / `smb` / `cli` / `webshell` …），
  按 ID 追踪活动会话
- 传输适配器：`SSHOwner` / `SSHSession`（含上传/下载/隧道）、
  `WinRMOpener` / `WinRMSession`、`SMBOpener` / `SMBSession`、
  `CLIOpener` / `CLISession`（本地命令执行）

## 给谁用

宿主 runtime：把 `Manager` 作为 `core.SessionManager` 端口注入，在装配期
注册需要的 opener；各后渗透 kit 通过该端口拿会话。

## 工具在哪里

工具**不在本包注册**：`session_open` / `session_exec` / `session_upload` /
`session_download` / `tunnel_open` / `session_list` / `session_close`
全部由 **`kits/shellkit`** 声明与分发（见 `kits/shellkit/capability.go`），
shellkit 把 capkit 端口转接给 sessionkit 的 `Manager`。本包因此是 **契约包，
无工具**：没有 `Manifest()`，没有 `ToolSpec`，也没有 `Call`。
