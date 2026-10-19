<?php
// 受保护页面：只有带合法登录态 cookie 才返回 200。
session_start();
if (!isset($_SESSION['user'])) { http_response_code(401); echo "no session"; exit; }
header('Content-Type: application/json');
echo json_encode(array("authorized" => true, "user" => $_SESSION['user']));
