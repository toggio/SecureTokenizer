# SecureTokenizer

A PHP Library for Cryptographically Secure Token Generation and Management

SecureTokenizer is a PHP library designed to enhance the security of web
applications by providing advanced capabilities for generating and managing
secure stateless tokens. This library integrates into PHP and AJAX projects,
offering a robust solution for creating unpredictable, authenticated tokens
suitable for request validation, attack mitigation, short-lived AJAX flows, and
encrypted data exchange.

It uses OpenSSL AES-256-GCM, native HKDF, SHA-256, and `random_bytes()` to
provide authenticated encryption, context binding, timed/refreshable tokens,
and stateless validation without a database, PHP session, cache, or server-side
token table.

## Features

- **Cryptographically secure token generation**: uses `random_bytes()` and
  OpenSSL AES-256-GCM authenticated encryption.
- **Stateless validation**: tokens carry their authenticated metadata inside the
  encrypted payload, so no database, cache, PHP session, or server-side token
  table is required.
- **Opaque hex format**: tokens are emitted as a single hex string. The visible
  bytes start with a random IV, so there is no stable prefix or cleartext token
  section. Plain, timed, and refreshable tokens have the same visible length.
- **Timed tokens**: `tokenCreate(false, 900)` creates an opaque token that
  expires after 15 minutes while staying fully stateless.
- **Refreshable tokens**: the browser sends its current token to the backend
  and receives a replacement token. No browser-side HMAC/proof key is needed.
- **AJAX integration**: repeated AJAX calls can update the in-memory token from
  the backend response without reloading the PHP page.
- **Same-server and same-client binding**: optionally binds tokens to
  `SERVER_ADDR` and/or `REMOTE_ADDR` independently.
- **Encrypted data helpers**: `encrypt()` and `decrypt()` expose compact
  authenticated encryption for post-validation data exchange.

## Security Scope

SecureTokenizer is designed for stateless request validation and short-lived
PHP/AJAX flows. Timed and refreshable tokens reduce replay exposure by using
short validity periods plus an absolute `valid_until` limit.

The default same-server binding (`ssb`) and same-client binding (`scb`) add an
additional stateless replay mitigation: a token is authenticated against the
expected `SERVER_ADDR` and `REMOTE_ADDR`, so a copied token resent from a
different server context or client IP is rejected when those bindings are
enabled and stable.

## Requirements

- PHP with `random_bytes()` and `hash_hkdf()` support
- OpenSSL extension with `aes-256-gcm` support

## Installation

Include the single PHP file:

```php
require_once 'path/to/SecureTokenizer.php';
```

## Quick Start Guide

### Initializing The Class

```php
$key = 'demo-only-change-this-32-byte-minimum-key';
$tokenizer = new secureTokenizer($key);
```

The explicit key above keeps the quick start copy-and-run. It is a demo key,
not a production secret.

### Generating A Secure Token

```php
$secureToken = $tokenizer->tokenCreate();
echo $secureToken;
```

### Verifying A Token

```php
// The token you receive, for example from a form or AJAX request.
$secureToken = 'paste-the-token-here';

if ($tokenizer->checkToken($secureToken)) {
    echo 'Token is valid.';
}
```

In production, store the application key outside the source code and read it
from configuration:

```php
$key = getenv('SECURETOKENIZER_KEY');
if ($key === false || $key === '') {
    // Demo fallback only. Set SECURETOKENIZER_KEY in real deployments.
    $key = 'demo-only-7c29cdb0e6d1b8f44e1f3a9d5c8420ea463b9f1c7d2e8564a0b3c6d8e9f2a1b';
}

$tokenizer = new secureTokenizer($key);
```

## Token Modes

```php
// Opaque stateless token with no expiration.
$token = $tokenizer->tokenCreate();

// Opaque stateless token valid for 15 minutes.
$token = $tokenizer->tokenCreate(false, 900);

// Refreshable token with defaults: 60 seconds per token, 1 day maximum.
$token = $tokenizer->tokenCreate(true);

// Refreshable token: each token lasts 30 seconds; the whole chain lasts 2 hours.
$token = $tokenizer->tokenCreate(true, 30, 7200);
```

## Timed And Refreshable Tokens

```php
$key = getenv('SECURETOKENIZER_KEY');
if ($key === false || $key === '') {
    // Demo fallback only. Set SECURETOKENIZER_KEY in real deployments.
    $key = 'demo-only-7c29cdb0e6d1b8f44e1f3a9d5c8420ea463b9f1c7d2e8564a0b3c6d8e9f2a1b';
}

$tokenizer = new secureTokenizer($key);

$secureToken = $tokenizer->tokenCreate(true);

if ($tokenizer->checkToken($secureToken)) {
    $newToken = $tokenizer->tokenRefresh($secureToken);
}
```

Calling `tokenCreate(true)` creates a refreshable token with these defaults:

- per-token lifetime: `60` seconds
- maximum token-chain lifetime: `86400` seconds, one day

You can override both values:

```php
// Each token lasts 30 seconds; the refresh chain can continue for 2 hours.
$token = $tokenizer->tokenCreate(true, 30, 7200);
```

The payload is encrypted and authenticated. Timed payloads contain the
per-token lifetime, the current token expiration, the absolute maximum validity
timestamp, and an informational counter. The backend key never leaves PHP.

`$tokenLifetime` is the validity window for the single token currently emitted.
`$maxTokenLifetime` is the absolute cap for the whole token chain. The current
token's `expires_at` is capped to `valid_until` too, so a token chain that is
about to end cannot create a token that lives past that final limit.

`tokenCreate(false, 900)` is the compact way to create a timed token without a
longer refresh chain. Internally, its `$tokenLifetime` and `$maxTokenLifetime`
are both 900 seconds. Calling `tokenRefresh()` before it expires may re-emit a
replacement token, but it cannot extend the original 15-minute validity window.

Plain, timed, and refreshable tokens are all 92 hex characters. Plain tokens
include encrypted random padding so the token type is not leaked by the
external length.

## Practical Use Case Example: Repeated AJAX Calls

For repeated AJAX calls, script 1 emits the initial token into JavaScript. The
browser sends the current token to script 2. Script 2 validates it and returns a
replacement token. The browser then replaces its in-memory token.

```php
<?php
require_once 'SecureTokenizer.php';

$key = getenv('SECURETOKENIZER_KEY');
if ($key === false || $key === '') {
    // Demo fallback only. Set SECURETOKENIZER_KEY in real deployments.
    $key = 'demo-only-7c29cdb0e6d1b8f44e1f3a9d5c8420ea463b9f1c7d2e8564a0b3c6d8e9f2a1b';
}

$tokenizer = new secureTokenizer($key);
$secureToken = $tokenizer->tokenCreate(true, 30, 7200);
?>

<button type="button" id="sendRequest">Send protected request</button>
<pre id="result">Ready.</pre>

<script>
let token = <?php echo json_encode($secureToken); ?>;
const result = document.getElementById('result');

async function sendProtectedRequest() {
    const response = await fetch('AjaxRefreshReceiver.php?token=' + encodeURIComponent(token), {
        credentials: 'same-origin'
    });
    const data = await response.json();

    if (data.token) {
        token = data.token;
    }

    result.textContent = data.message;
}
</script>
```

Use `json_encode($secureToken)` when writing the token into JavaScript. The
token is hex, but `json_encode()` still keeps the PHP-to-JavaScript boundary
correct and avoids manual string escaping.

**AjaxRefreshReceiver.php**

```php
<?php
require_once 'SecureTokenizer.php';

$key = getenv('SECURETOKENIZER_KEY');
if ($key === false || $key === '') {
    // Demo fallback only. Set SECURETOKENIZER_KEY in real deployments.
    $key = 'demo-only-7c29cdb0e6d1b8f44e1f3a9d5c8420ea463b9f1c7d2e8564a0b3c6d8e9f2a1b';
}

$tokenizer = new secureTokenizer($key);

// Production-friendly path: X-Secure-Token header.
// Debug fallback: GET keeps the token visible and directly openable.
$headerToken = isset($_SERVER['HTTP_X_SECURE_TOKEN']) ? (string) $_SERVER['HTTP_X_SECURE_TOKEN'] : '';
$token = $headerToken !== '' ? $headerToken : (isset($_GET['token']) ? (string) $_GET['token'] : '');
$isTokenValid = $token !== '' && $tokenizer->checkToken($token);
$newToken = $isTokenValid ? $tokenizer->tokenRefresh($token) : false;

if (!$isTokenValid) {
    http_response_code(401);
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
echo json_encode([
    'valid' => $isTokenValid,
    'token' => $newToken === false ? null : $newToken,
    'message' => $isTokenValid ? 'Token is valid.' : 'Token is invalid.',
], JSON_UNESCAPED_SLASHES);
?>
```

JSON response format:

```json
{
  "valid": true,
  "token": "92-hex-character-refreshed-token-or-null",
  "message": "Token is valid."
}
```

- `valid`: boolean validation result for the submitted token.
- `token`: refreshed token when validation and refresh succeed, otherwise
  `null`.
- `message`: short human-readable status string.

The AJAX refresh example supports `X-Secure-Token` and also accepts GET as a
debug transport: the generated URL can be opened directly in the browser,
copied into another test client, and inspected while checking
same-server/same-client binding behavior. Treat GET as a testing convenience
only. In production, prefer `X-Secure-Token` or a POST body so tokens are not
stored in browser history, server logs, reverse-proxy logs, `Referer` headers,
or analytics URLs. Invalid requests return HTTP `401` with the same JSON shape.

## Constructor

```php
$tokenizer = new secureTokenizer($key, true, true); // $ssb, $scb
```

- `string|null $key`: application secret used to derive encryption and
  authentication keys. Use the same strong key to create and validate tokens.
  Pass at least 32 bytes of secret material from configuration, an environment
  variable, or a secret manager. SecureTokenizer emits a warning when the
  provided key is shorter than 32 bytes. If omitted or empty, it generates a
  random runtime key.
  That is useful only inside the same tokenizer object; tokens created with that
  random key will not validate in another object, across independent requests,
  page loads, different scripts, or different servers. For real use, always
  pass a stable secret from configuration. The key is private inside the class;
  use `changeKey()` if it must be replaced at runtime.
- `bool $ssb`: same-server binding. When true, tokens are bound to
  `SERVER_ADDR`; a receiver with a different server context rejects the token.
- `bool $scb`: same-client binding. When true, tokens are bound to
  `REMOTE_ADDR`; a request from a different client IP rejects the token.

## Context Binding: `ssb` And `scb`

Both bindings are enabled by default:

```php
$tokenizer = new secureTokenizer($key);             // same as true, true
$tokenizer = new secureTokenizer($key, true, true); // explicit ssb/scb
```

- `ssb` means same-server binding. The token is authenticated against the
  current `SERVER_ADDR`. Disable it only when the sender and receiver
  intentionally run behind different server addresses or a load-balanced setup
  where that value is not stable.
- `scb` means same-client binding. The token is authenticated against the
  current `REMOTE_ADDR`. Disable it when proxies, CDNs, mobile networks, or load
  balancers make the client address change between requests.

These bindings are network-context checks and work best when the server and
client addresses are stable for the lifetime of the token.

## Customization And Advanced Usage

SecureTokenizer can be configured with independent same-server and same-client
binding, custom per-token lifetimes, custom maximum refresh-chain lifetimes,
clock-skew tolerance for timed checks, and the encrypted exchange helper methods
described below.

## Public Properties And Methods

### Properties

- `int $defaultTokenLifetime`: default per-token lifetime, in seconds, when the
  second `tokenCreate()` argument is omitted. Default: `60`.
- `int $defaultMaxTokenLifetime`: default maximum token-chain lifetime, in
  seconds, when the third `tokenCreate()` argument is omitted. Default:
  `86400`.

### Methods

- `changeKey(string $key): void`
  Replaces the configured application key and clears the derived exchange key.
  Use this method instead of modifying internals directly.
- `getExchangeKey(): string`
  Returns the binary key derived after `tokenCreate()` or successful
  `checkToken()`. Both PHP scripts can use it with `encrypt()` / `decrypt()` to
  exchange encrypted data after the token has been accepted. After
  `tokenRefresh()`, the exchange key still refers to the token accepted for
  the current request, which is normally the right key for protecting the
  response to that request.
  Calling `checkToken()` later on the returned token derives the returned
  token's own exchange key.
- `tokenCreate(bool $refreshable = false, int|null $tokenLifetime = null, int|null $maxTokenLifetime = null): string`
  Creates an authenticated token. With no lifetime it creates a plain opaque
  token with no expiration. With `$refreshable = false` and `$tokenLifetime`
  set, it creates a timed token whose maximum lifetime equals the current token
  lifetime. With `$refreshable = true`, `$tokenLifetime` is the validity window
  for each emitted token and `$maxTokenLifetime` is the maximum total lifetime
  for the whole refresh chain. Both values are clamped to 1 second through 366
  days.
- `checkToken(string $string, int $tolerance = 0): bool`
  Validates authenticity, same-server binding, same-client binding, token
  format, and optional expiration. Plain/timed format is read from the encrypted
  flags after authentication succeeds. On success, derives the exchange key
  readable through `getExchangeKey()`. `$tolerance` is a clock-skew allowance in
  seconds for timed token expiration checks. It is clamped to a maximum of
  `300` seconds because larger values would extend the accepted replay window
  too much.
- `tokenRefresh(string $string, int $tolerance = 0): string|false`
  Validates a timed token and returns a replacement token with a fresh
  expiration, preserving the same token lifetime and absolute maximum validity
  limit. Returns `false` if the token is invalid, expired, plain, or past
  `valid_until`. The method leaves the exchange key set to the token accepted
  for the current request, readable through `getExchangeKey()`. `$tolerance`
  has the same clock-skew meaning and `300` second maximum as in
  `checkToken()`.
- `encrypt(string $string, string $key = null): string`
  Encrypts arbitrary binary/text data and returns a binary encrypted frame. Use
  `bin2hex()` or base64 if you need to store or transmit it as text.
- `decrypt(string $string, string $key = null): string|false`
  Decrypts data produced by `encrypt()` and returns `false` on authentication
  failure.

## How It Works

1. A compact 18-byte binary payload is built. Plain tokens contain version,
   flags, and random padding. Timed tokens contain version, flags,
   token lifetime, expiration, maximum validity timestamp, and a counter.
2. Native `hash_hkdf()` derives purpose-specific keys from the application key
   and the enabled same-server/same-client binding context.
3. OpenSSL AES-256-GCM encrypts and authenticates the payload. The binary frame
   is `randomIV | authenticationTag | ciphertext`, then hex-encoded. Plain and
   timed tokens use the same token AAD and the same frame length.
4. For AJAX refresh, the client sends the current token to the backend. The
   backend validates it, checks `expires_at` and `valid_until`, and returns a
   new opaque token.
5. On token creation or successful validation, SecureTokenizer derives an
   exchange key from the accepted token frame. Read it with `getExchangeKey()`
   when the two PHP scripts need to exchange encrypted data without exposing
   the backend key.

## Examples

- `examples/BasicExample.php`: compact report for plain, timed, and refreshable tokens.
- `examples/AjaxRefreshSender.php`: minimal browser UI with refresh timing/state details.
- `examples/AjaxRefreshReceiver.php`: token verification and refresh endpoint.

The example files read `SECURETOKENIZER_KEY` when it is available. If it is not
set, they use a public demo fallback so the examples can run immediately. Do
not use that fallback key in production.

## Help us

If you find this project useful and would like to support its development,
consider making a donation. Any contribution is greatly appreciated!

**Bitcoin (BTC) Addresses:**

- **1LToggio**f3rNUTCemJZSsxd1qubTYoSde6
- **3LToggio**7Xx8qMsjCFfiarV4U2ZR9iU9ob

## License

SecureTokenizer is licensed under the Apache License, Version 2.0. You are free
to use, modify, and distribute the library in compliance with the license.

Copyright (C) 2024-2026 Luca Soltoggio - https://www.lucasoltoggio.it/
