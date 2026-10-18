# shellkit/memshell (private)

Pure memory-shell payload generator ported from 4zreco. **No I/O and no
default deployer.**

Supported kinds:

- `jsp-tomcat-filter` (Tomcat 7-9)
- `jsp-tomcat-filter-jakarta` (Tomcat 10/11)
- `jsp-tomcat-valve`
- `jsp-tomcat-servlet`
- `jsp-spring-controller`
- `aspx-httpmodule`
- `php-user-ini`

`deploy.go` defines `DeployPlan` and the host-provided `Deployer` interface.
The host must implement:

1. writing the injector (and `ExtraFiles`) via its session executor,
2. triggering the injector URL,
3. optionally registering a session,
4. removing the injector and (for supported kinds) the memory shell.

Never add a default file writer or trigger client here.
