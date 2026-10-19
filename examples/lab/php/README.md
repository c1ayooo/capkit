# M2 exit-test target

Deliberately vulnerable PHP target used for the ROADMAP M2 exit test. Three
surfaces:

- `exec.php?ip=` — command injection (`echo PING $ip` into `shell_exec`), and the
  writable web root a dropped WebShell lands in.
- `login.php` — form login with a CSRF token; account `alice` / `correct-horse-battery`.
- `userinfo.php` — protected page that answers 200 only with a valid session cookie.

Build and run (loopback only; port 18080 is free on the M2 host):

```bash
docker build -t capkit-lab:latest examples/lab/php
docker run -d --rm --name capkit-lab -p 127.0.0.1:18080:80 capkit-lab:latest
```

Then:

```bash
go run ./examples/webshell-chain   -base http://127.0.0.1:18080 -dir /var/www/html
go run ./examples/identity-login   -base http://127.0.0.1:18080 \
  -login-path /login.php -userinfo-path /userinfo.php \
  -user alice -password correct-horse-battery
```

Never expose this container beyond loopback.
