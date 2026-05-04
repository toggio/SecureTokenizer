<?php
require_once __DIR__ . '/../SecureTokenizer.php';

$key = getenv('SECURETOKENIZER_KEY');
if ($key === false || $key === '') {
    // Demo fallback only. Set SECURETOKENIZER_KEY in real deployments.
    $key = 'demo-only-7c29cdb0e6d1b8f44e1f3a9d5c8420ea463b9f1c7d2e8564a0b3c6d8e9f2a1b';
}

$tokenizer = new secureTokenizer($key);

// Production-friendly path: X-Secure-Token header.
// Debug fallback: GET keeps the token visible and directly openable.
$headerToken = isset($_SERVER['HTTP_X_SECURE_TOKEN']) ? (string) $_SERVER['HTTP_X_SECURE_TOKEN'] : '';
$secureToken = $headerToken !== '' ? $headerToken : (isset($_GET['token']) ? (string) $_GET['token'] : '');

$isTokenValid = $secureToken !== '' && $tokenizer->checkToken($secureToken);
$refreshedToken = $isTokenValid ? $tokenizer->tokenRefresh($secureToken) : false;

if (!$isTokenValid) {
    http_response_code(401);
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
echo json_encode([
    'valid' => $isTokenValid,
    'token' => $refreshedToken === false ? null : $refreshedToken,
    'message' => $isTokenValid ? 'Token is valid.' : 'Token is invalid.',
], JSON_UNESCAPED_SLASHES);
?>
