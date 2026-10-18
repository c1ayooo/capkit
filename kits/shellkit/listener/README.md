# shellkit/listener

A small Go reverse-shell listener and session manager.

- `Manager.Start("0.0.0.0:4444")` accepts reverse shells and registers sessions.
- `Manager.Exec(sessionID, command)` runs a non-interactive command using a
  unique echo marker (serialized per session, deadline-aware).
- `Manager.Upload` writes a file in 32KB base64 chunks (POSIX shells).
- `Manager.Download` reads a file as base64 (POSIX shells).
- `Manager.Sessions` / `Manager.Stop` list or close sessions.

This is **not** a C2: no staging, persistence, evasion, or automatic lateral
movement. It is the transport/session layer for authorized reverse shells.
WebSocket/terminal UI is host-side; the host can stream `Exec` results or add a
session stream.
