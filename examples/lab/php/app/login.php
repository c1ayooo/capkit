<?php
// 带 CSRF 的表单登录页，POST 成功则写 session cookie。
session_start();
if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(8)); }
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html><body><form method="post" action="/login.php">'
       . '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($_SESSION['csrf']) . '">'
       . '<input name="username"><input name="password" type="password">'
       . '<button type="submit">login</button></form></body></html>';
    exit;
}
if ($_POST['csrf_token'] !== $_SESSION['csrf']) { http_response_code(403); echo 'bad csrf'; exit; }
if ($_POST['username'] === 'alice' && $_POST['password'] === 'correct-horse-battery') {
    $_SESSION['user'] = 'alice';
    echo 'logged in as alice';
    exit;
}
http_response_code(401); echo 'bad credentials';
