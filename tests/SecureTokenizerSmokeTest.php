<?php
require_once __DIR__ . '/../SecureTokenizer.php';

function st_fail($message) {
    fwrite(STDERR, "FAIL: " . $message . PHP_EOL);
    exit(1);
}

function st_assert($condition, $message) {
    if (!$condition) {
        st_fail($message);
    }
}

function st_context($serverAddress, $clientAddress) {
    $_SERVER['SERVER_ADDR'] = $serverAddress;
    $_SERVER['REMOTE_ADDR'] = $clientAddress;
}

$key = str_repeat('k', 32);

st_context('10.0.0.1', '198.51.100.10');
$tokenizer = new secureTokenizer($key);

$plainToken = $tokenizer->tokenCreate();
st_assert(strlen($plainToken) === 92, 'plain token length must be 92 hex chars');
st_assert($tokenizer->checkToken($plainToken), 'plain token must validate');
st_assert(strlen($tokenizer->getExchangeKey()) === 32, 'exchange key must be 32 bytes');
st_assert($tokenizer->tokenRefresh($plainToken) === false, 'plain token must not refresh');

$encrypted = $tokenizer->encrypt('secret payload', $tokenizer->getExchangeKey());
st_assert($tokenizer->decrypt($encrypted, $tokenizer->getExchangeKey()) === 'secret payload', 'exchange encryption round-trip failed');
st_assert($tokenizer->decrypt(substr_replace($encrypted, chr(ord($encrypted[0]) ^ 1), 0, 1), $tokenizer->getExchangeKey()) === false, 'tampered encrypted data must fail');

$timedToken = $tokenizer->tokenCreate(false, 900);
st_assert(strlen($timedToken) === 92, 'timed token length must be 92 hex chars');
st_assert($tokenizer->checkToken($timedToken), 'timed token must validate');

$refreshableToken = $tokenizer->tokenCreate(true, 30, 7200);
$refreshedToken = $tokenizer->tokenRefresh($refreshableToken);
st_assert(is_string($refreshedToken), 'refreshable token must refresh');
st_assert(strlen($refreshedToken) === 92, 'refreshed token length must be 92 hex chars');
st_assert($tokenizer->checkToken($refreshedToken), 'refreshed token must validate');

$tamperedToken = substr_replace($refreshableToken, $refreshableToken[0] === '0' ? '1' : '0', 0, 1);
st_assert(!$tokenizer->checkToken($tamperedToken), 'tampered token must fail');
st_assert(!(new secureTokenizer(str_repeat('x', 32)))->checkToken($plainToken), 'wrong key must fail');

st_context('10.0.0.1', '198.51.100.11');
st_assert(!(new secureTokenizer($key))->checkToken($plainToken), 'same-client binding must reject a different client');

st_context('10.0.0.2', '198.51.100.10');
st_assert(!(new secureTokenizer($key))->checkToken($plainToken), 'same-server binding must reject a different server');

st_context('10.0.0.1', '198.51.100.10');
$expiringTokenizer = new secureTokenizer($key);
$expiredToken = $expiringTokenizer->tokenCreate(false, 1);
sleep(2);
st_assert(!$expiringTokenizer->checkToken($expiredToken), 'expired token must fail without tolerance');
st_assert($expiringTokenizer->checkToken($expiredToken, 300), 'expired token inside tolerance must validate');
st_assert(!$expiringTokenizer->checkToken($expiredToken, -1), 'negative tolerance must not extend token validity');

$shortChain = $expiringTokenizer->tokenCreate(true, 1, 1);
sleep(2);
st_assert($expiringTokenizer->tokenRefresh($shortChain, 300) === false, 'refresh must not extend valid_until with tolerance');

$warningCaught = false;
set_error_handler(function () use (&$warningCaught) {
    $warningCaught = true;
});
new secureTokenizer('short');
restore_error_handler();
st_assert($warningCaught, 'weak key warning must be emitted');

echo "SecureTokenizer smoke test OK" . PHP_EOL;
