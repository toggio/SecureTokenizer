<?php
require_once __DIR__ . '/../SecureTokenizer.php';

$key = getenv('SECURETOKENIZER_KEY');
if ($key === false || $key === '') {
    // Demo fallback only. Set SECURETOKENIZER_KEY in real deployments.
    $key = 'demo-only-7c29cdb0e6d1b8f44e1f3a9d5c8420ea463b9f1c7d2e8564a0b3c6d8e9f2a1b';
}

$tokenizer = new secureTokenizer($key);
$tokenLifetime = 30;
$maxTokenLifetime = 7200;
$autoRefreshInterval = 10;
$issuedAt = time();
$secureToken = $tokenizer->tokenCreate(true, $tokenLifetime, $maxTokenLifetime);
$tokenExpiresAt = $issuedAt + $tokenLifetime;
$chainExpiresAt = $issuedAt + $maxTokenLifetime;
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SecureTokenizer AJAX Refresh</title>
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
            --button: #25313d;
            --button-text: #ffffff;
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

        .toolbar {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }

        button {
            appearance: none;
            background: var(--button);
            border: 1px solid var(--button);
            border-radius: 6px;
            color: var(--button-text);
            cursor: pointer;
            font: inherit;
            font-weight: 650;
            min-height: 36px;
            padding: 7px 12px;
        }

        button.secondary {
            background: #ffffff;
            color: var(--button);
        }

        button:disabled {
            cursor: progress;
            opacity: 0.7;
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
        <h1>SecureTokenizer AJAX Refresh</h1>
        <p class="muted">Refreshable token flow with visible timing and request state.</p>
    </header>

    <div class="grid">
        <section class="panel">
            <div class="head">
                <h2>Refresh setup</h2>
                <span id="status" class="status valid">ready</span>
            </div>
            <dl>
                <dt>PHP call</dt>
                <dd><code class="code-line call">$secureToken = $tokenizer-&gt;tokenCreate(true, 30, 7200);</code></dd>
                <dt>Refresh call</dt>
                <dd><code class="code-line call">$refreshedToken = $tokenizer-&gt;tokenRefresh($secureToken);</code></dd>
                <dt>Request URL</dt>
                <dd><code class="code-line">AjaxRefreshReceiver.php?token=&lt;current-token&gt;</code></dd>
                <dt>Token lifetime / slot</dt>
                <dd><?php echo $tokenLifetime; ?> seconds</dd>
                <dt>Maximum validity</dt>
                <dd><?php echo $maxTokenLifetime; ?> seconds</dd>
                <dt>Auto refresh interval</dt>
                <dd><?php echo $autoRefreshInterval; ?> seconds</dd>
                <dt>Initial expires at</dt>
                <dd><?php echo date('H:i:s', $tokenExpiresAt); ?></dd>
                <dt>Chain valid until</dt>
                <dd><?php echo date('H:i:s', $chainExpiresAt); ?></dd>
            </dl>
        </section>

        <section class="panel">
            <div class="head">
                <h2>Request controls</h2>
            </div>
            <div class="toolbar">
                <button type="button" id="sendRequest">Send request</button>
                <button type="button" id="toggleAuto" class="secondary">Start auto refresh</button>
            </div>
        </section>

        <section class="panel">
            <div class="head">
                <h2>Current token</h2>
            </div>
            <dl>
                <dt>Requests</dt>
                <dd id="requestCount">0</dd>
                <dt>Current token expires in</dt>
                <dd id="tokenExpiresIn">0 seconds</dd>
                <dt>Chain expires in</dt>
                <dd id="chainExpiresIn">0 seconds</dd>
                <dt>Token length</dt>
                <dd id="tokenLength">0 chars</dd>
                <dt>Token</dt>
                <dd><code id="currentToken" class="code-line"></code></dd>
            </dl>
        </section>

        <section class="panel">
            <div class="head">
                <h2>Last response</h2>
            </div>
            <dl>
                <dt>Time</dt>
                <dd id="lastTime">never</dd>
                <dt>Valid</dt>
                <dd id="lastValid">not sent</dd>
                <dt>Message</dt>
                <dd id="lastMessage">Waiting for first request.</dd>
                <dt>Sent length</dt>
                <dd id="sentLength">0 chars</dd>
                <dt>Received length</dt>
                <dd id="receivedLength">0 chars</dd>
                <dt>Received token</dt>
                <dd><code id="receivedToken" class="code-line"></code></dd>
            </dl>
        </section>

        <section class="panel">
            <div class="head">
                <h2>Production note</h2>
            </div>
            <dl>
                <dt>Example transport</dt>
                <dd>GET is debug-only here so the generated URL can be opened directly and copied during tests.</dd>
                <dt>Production transport</dt>
                <dd>Prefer an <code>X-Secure-Token</code> header or a POST body to avoid tokens in browser history, server logs, proxy logs, and referer headers.</dd>
            </dl>
        </section>
    </div>
</main>

<script>
    const status = document.getElementById('status');
    const requestCountLabel = document.getElementById('requestCount');
    const tokenExpiresIn = document.getElementById('tokenExpiresIn');
    const chainExpiresIn = document.getElementById('chainExpiresIn');
    const tokenLength = document.getElementById('tokenLength');
    const currentToken = document.getElementById('currentToken');
    const lastTime = document.getElementById('lastTime');
    const lastValid = document.getElementById('lastValid');
    const lastMessage = document.getElementById('lastMessage');
    const sentLength = document.getElementById('sentLength');
    const receivedLength = document.getElementById('receivedLength');
    const receivedToken = document.getElementById('receivedToken');
    const sendButton = document.getElementById('sendRequest');
    const autoButton = document.getElementById('toggleAuto');

    const tokenLifetimeSeconds = <?php echo json_encode($tokenLifetime); ?>;
    const maxTokenLifetimeSeconds = <?php echo json_encode($maxTokenLifetime); ?>;
    const autoRefreshIntervalSeconds = <?php echo json_encode($autoRefreshInterval); ?>;

    let autoTimer = null;
    let requestCount = 0;
    let token = <?php echo json_encode($secureToken); ?>;
    let tokenExpiresAt = Date.now() + tokenLifetimeSeconds * 1000;
    let chainExpiresAt = Date.now() + maxTokenLifetimeSeconds * 1000;

    function secondsLeft(timestamp) {
        return Math.max(0, Math.ceil((timestamp - Date.now()) / 1000));
    }

    function setStatus(label, valid) {
        status.textContent = label;
        status.className = 'status ' + (valid ? 'valid' : 'invalid');
    }

    function renderState() {
        requestCountLabel.textContent = String(requestCount);
        tokenExpiresIn.textContent = secondsLeft(tokenExpiresAt) + ' seconds';
        chainExpiresIn.textContent = secondsLeft(chainExpiresAt) + ' seconds';
        tokenLength.textContent = token.length + ' chars';
        currentToken.textContent = token;
    }

    async function sendProtectedRequest() {
        const previousToken = token;
        const url = 'AjaxRefreshReceiver.php?token=' + encodeURIComponent(token);

        sendButton.disabled = true;
        setStatus('sending', true);
        renderState();

        try {
            const response = await fetch(url, {
                credentials: 'same-origin'
            });
            const data = await response.json();

            requestCount += 1;
            lastTime.textContent = new Date().toLocaleTimeString();
            lastValid.textContent = String(data.valid);
            lastMessage.textContent = data.message;
            sentLength.textContent = previousToken.length + ' chars';
            receivedLength.textContent = (data.token ? data.token.length : 0) + ' chars';
            receivedToken.textContent = data.token || '';

            if (data.token) {
                token = data.token;
                tokenExpiresAt = Math.min(Date.now() + tokenLifetimeSeconds * 1000, chainExpiresAt);
            }

            setStatus(data.valid ? 'valid' : 'invalid', data.valid);
            renderState();
        } catch (error) {
            lastTime.textContent = new Date().toLocaleTimeString();
            lastValid.textContent = 'false';
            lastMessage.textContent = 'Fetch error: ' + error.message;
            setStatus('request failed', false);
            renderState();
        } finally {
            sendButton.disabled = false;
        }
    }

    sendButton.addEventListener('click', sendProtectedRequest);
    autoButton.addEventListener('click', function () {
        if (autoTimer) {
            clearInterval(autoTimer);
            autoTimer = null;
            autoButton.textContent = 'Start auto refresh';
            autoButton.classList.add('secondary');
            return;
        }

        sendProtectedRequest();
        autoTimer = setInterval(sendProtectedRequest, autoRefreshIntervalSeconds * 1000);
        autoButton.textContent = 'Stop auto refresh';
        autoButton.classList.remove('secondary');
    });

    renderState();
    setInterval(renderState, 1000);
</script>
</body>
</html>
