# toolparse

Structured output parsers for security CLIs, ported from 4zreco.

Supported tools (registry key):

`httpx`, `ffuf`, `katana`, `nuclei`, `nmap`, `sqlmap`, `dirsearch`, `dalfox`,
`arjun`, `wpscan`, `wafw00f`, `nikto`, `whatweb`, `fscan`, `hashcat`, `john`.

Each parser turns raw stdout/stderr into:

- `Fields`: scalar key facts (counts, DBMS, ports, technology, ...)
- `Facts`: normalized candidates (`finding/...`, `target/...`, `infra/...`,
  `auth/...`) with confidence and links
- `RawRef`: caller-provided raw evidence path

No database or host dependency: the host decides whether/how to persist facts.
Parsers are fail-closed: malformed/truncated input yields no facts.
