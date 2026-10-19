<?php
// 故意漏洞靶页：命令注入。仅供 capkit M2 实测使用。
// ip 参数直接拼进 shell 命令行，于是 `1;id` 之类会执行任意命令。
$ip = isset($_GET['ip']) ? $_GET['ip'] : '';
header('Content-Type: text/plain; charset=utf-8');
echo shell_exec('echo PING ' . $ip . ' 2>&1');
