<?php
require_once __DIR__ . '/../SecureTokenizer.php';

function h($value) {
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function statusText($valid) {
    return $valid ? 'valid' : 'invalid';
}

$key = getenv('SECURETOKENIZER_KEY');
if ($key === false || $key === '') {
    // Demo fallback only. Set SECURETOKENIZER_KEY in real deployments.
    $key = 'demo-only-7c29cdb0e6d1b8f44e1f3a9d5c8420ea463b9f1c7d2e8564a0b3c6d8e9f2a1b';
}

$tokenizer = new secureTokenizer($key);

$plainToken = $tokenizer->tokenCreate();
$plainValid = $tokenizer->checkToken($plainToken);
$plainExchangeKey = $plainValid ? $tokenizer->getExchangeKey() : '';
$plainEncrypted = $plainValid ? $tokenizer->encrypt('Secret message', $plainExchangeKey) : false;
$plainDecrypted = $plainEncrypted !== false ? $tokenizer->decrypt($plainEncrypted, $plainExchangeKey) : false;

$timedToken = $tokenizer->tokenCreate(false, 900);
$timedValid = $tokenizer->checkToken($timedToken);

$refreshableToken = $tokenizer->tokenCreate(true, 30, 3600);
$refreshableValid = $tokenizer->checkToken($refreshableToken);
$refreshedToken = $refreshableValid ? $tokenizer->tokenRefresh($refreshableToken) : false;
$refreshedValid = $refreshedToken !== false && $tokenizer->checkToken($refreshedToken);
$refreshableExchangeKey = $refreshedValid ? $tokenizer->getExchangeKey() : '';
$refreshableEncrypted = $refreshedValid ? $tokenizer->encrypt('Refreshable secret message', $refreshableExchangeKey) : false;
$refreshableDecrypted = $refreshableEncrypted !== false ? $tokenizer->decrypt($refreshableEncrypted, $refreshableExchangeKey) : false;
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SecureTokenizer Basic Example</title>
    <style>
        :root {
            color-scheme: light;
            --bg: #f5f7f9;
            --panel: #ffffff;
            --line: #d8dee5;
            --text: #1f2933;
            --muted: #62717f;
            --code: #0f1720;
            --ok-bg: #e8f5ed;
            --ok-text: #17663a;
            --bad-bg: #fdecec;
            --bad-text: #9f1d1d;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font: 14px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }

        main {
            max-width: 1100px;
            margin: 0 auto;
            padding: 32px 20px;
        }

        header {
            margin-bottom: 24px;
        }

        h1,
        h2 {
            margin: 0;
            font-weight: 650;
            letter-spacing: 0;
        }

        h1 {
            font-size: 24px;
        }

        h2 {
            font-size: 16px;
        }

        .muted {
            color: var(--muted);
            margin: 6px 0 0;
        }

        .grid {
            display: grid;
            gap: 16px;
        }

        .panel {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 18px;
        }

        .head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 14px;
        }

        .status {
            border-radius: 999px;
            padding: 3px 10px;
            font-size: 12px;
            font-weight: 650;
            text-transform: uppercase;
        }

        .status.valid {
            background: var(--ok-bg);
            color: var(--ok-text);
        }

        .status.invalid {
            background: var(--bad-bg);
            color: var(--bad-text);
        }

        dl {
            display: grid;
            grid-template-columns: 160px minmax(0, 1fr);
            gap: 8px 14px;
            margin: 0;
        }

        dt {
            color: var(--muted);
        }

        dd {
            margin: 0;
            min-width: 0;
        }

        code {
            font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
            font-size: 12px;
            color: var(--code);
            overflow-wrap: anywhere;
            word-break: break-word;
        }

        .code-line {
            display: block;
            background: #f8fafc;
            border: 1px solid var(--line);
            border-radius: 6px;
            padding: 8px 10px;
        }

        .call {
            background: #eaf2ff;
            border-color: #78a8e8;
            border-left: 4px solid #1a73e8;
            color: #0b4f8a;
            font-size: 13px;
        }

        @media (max-width: 720px) {
            main {
                padding: 22px 12px;
            }

            .head {
                align-items: flex-start;
                flex-direction: column;
            }

            dl {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
<main>
    <header>
        <h1>SecureTokenizer Basic Example</h1>
        <p class="muted">Minimal token generation, validation, refresh, and encrypted exchange checks.</p>
    </header>

    <div class="grid">
        <section class="panel">
            <div class="head">
                <h2>Plain token</h2>
                <span class="status <?php echo statusText($plainValid); ?>"><?php echo statusText($plainValid); ?></span>
            </div>
            <dl>
                <dt>PHP call</dt>
                <dd><code class="code-line call">$secureToken = $tokenizer-&gt;tokenCreate();</code></dd>
                <dt>Mode</dt>
                <dd>No expiration</dd>
                <dt>Length</dt>
                <dd><?php echo strlen($plainToken); ?> chars</dd>
                <dt>Token</dt>
                <dd><code class="code-line"><?php echo h($plainToken); ?></code></dd>
                <dt>Encrypted exchange</dt>
                <dd><code class="code-line"><?php echo $plainEncrypted === false ? 'failed' : h(bin2hex($plainEncrypted)); ?></code></dd>
                <dt>Decrypted exchange</dt>
                <dd><code class="code-line"><?php echo $plainDecrypted === false ? 'failed' : h($plainDecrypted); ?></code></dd>
            </dl>
        </section>

        <section class="panel">
            <div class="head">
                <h2>Timed token</h2>
                <span class="status <?php echo statusText($timedValid); ?>"><?php echo statusText($timedValid); ?></span>
            </div>
            <dl>
                <dt>PHP call</dt>
                <dd><code class="code-line call">$secureToken = $tokenizer-&gt;tokenCreate(false, 900);</code></dd>
                <dt>Mode</dt>
                <dd>Expires after 900 seconds</dd>
                <dt>Length</dt>
                <dd><?php echo strlen($timedToken); ?> chars</dd>
                <dt>Token</dt>
                <dd><code class="code-line"><?php echo h($timedToken); ?></code></dd>
            </dl>
        </section>

        <section class="panel">
            <div class="head">
                <h2>Refreshable token</h2>
                <span class="status <?php echo statusText($refreshedValid); ?>"><?php echo statusText($refreshedValid); ?></span>
            </div>
            <dl>
                <dt>PHP call</dt>
                <dd><code class="code-line call">$secureToken = $tokenizer-&gt;tokenCreate(true, 30, 3600);</code></dd>
                <dt>Mode</dt>
                <dd>30 seconds per token, 3600 seconds max chain</dd>
                <dt>Initial length</dt>
                <dd><?php echo strlen($refreshableToken); ?> chars</dd>
                <dt>Initial token</dt>
                <dd><code class="code-line"><?php echo h($refreshableToken); ?></code></dd>
                <dt>Refreshed length</dt>
                <dd><?php echo $refreshedToken === false ? 'failed' : strlen($refreshedToken) . ' chars'; ?></dd>
                <dt>Refreshed token</dt>
                <dd><code class="code-line"><?php echo $refreshedToken === false ? 'failed' : h($refreshedToken); ?></code></dd>
                <dt>Refresh call</dt>
                <dd><code class="code-line call">$refreshedToken = $tokenizer-&gt;tokenRefresh($secureToken);</code></dd>
                <dt>Encrypted exchange</dt>
                <dd><code class="code-line"><?php echo $refreshableEncrypted === false ? 'failed' : h(bin2hex($refreshableEncrypted)); ?></code></dd>
                <dt>Decrypted exchange</dt>
                <dd><code class="code-line"><?php echo $refreshableDecrypted === false ? 'failed' : h($refreshableDecrypted); ?></code></dd>
            </dl>
        </section>
    </div>
</main>
</body>
</html>
