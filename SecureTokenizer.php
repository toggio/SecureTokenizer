<?php
/*
 * Secure Tokenizer Class (SecureTokenizer) v3.3.0 - 28 April 2026
 *
 * A PHP Library for Cryptographically Secure Token Generation and Management
 *
 * SecureTokenizer is a sophisticated PHP library designed
 * to enhance web application security by providing advanced
 * capabilities for generating and managing secure stateless tokens.
 * This library integrates into PHP/AJAX projects,
 * offering a robust solution for creating unpredictable,
 * authenticated tokens suitable for request validation,
 * attack mitigation, short-lived AJAX flows, and encrypted data exchange.
 *
 * Copyright (C) 2024-2026 under Apache License, Version 2.0
 *
 * @author Luca Soltoggio
 * https://www.lucasoltoggio.it
 * https://github.com/toggio/SecureTokenizer
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

class secureTokenizer {
    private const FORMAT_VERSION = 7;
    private const CIPHER = 'aes-256-gcm';
    private const MIN_KEY_BYTES = 32;
    private const IV_BYTES = 12;
    private const TAG_BYTES = 16;
    private const TOKEN_PAYLOAD_BYTES = 18;
    private const DEFAULT_TOKEN_LIFETIME_SECONDS = 60;
    private const MIN_TOKEN_LIFETIME_SECONDS = 1;
    private const MAX_TOKEN_LIFETIME_SECONDS = 31622400;
    private const DEFAULT_MAX_TOKEN_LIFETIME_SECONDS = 86400;
    private const MIN_MAX_TOKEN_LIFETIME_SECONDS = 1;
    private const MAX_MAX_TOKEN_LIFETIME_SECONDS = 31622400;
    private const MAX_TOLERANCE_SECONDS = 300;
    private const TOKEN_FLAGS_PLAIN = 0;
    private const TOKEN_FLAGS_TIMED = 1;

    public $defaultTokenLifetime = 60;
    public $defaultMaxTokenLifetime = 86400;

    private $key;
    private $exchangeKey = '';
    private $clientAddress = '127.0.0.1';
    private $serverAddress = '127.0.0.1';
    private $ssb = true;
    private $scb = true;

    /** Creates a tokenizer with a shared key and optional server/client binding. */
    public function __construct($key = null, $ssb = true, $scb = true) {
        $this->key = $this->normalizeKey($key);
        $this->ssb = (bool) $ssb;
        $this->scb = (bool) $scb;

        if ($this->ssb && isset($_SERVER['SERVER_ADDR'])) {
            $this->serverAddress = (string) $_SERVER['SERVER_ADDR'];
        }

        if ($this->scb && isset($_SERVER['REMOTE_ADDR'])) {
            $this->clientAddress = (string) $_SERVER['REMOTE_ADDR'];
        }

        $this->assertOpenSslGcm();
    }

    public function changeKey($key) {
        $this->key = $this->normalizeKey($key);
        $this->exchangeKey = '';
    }

    /** Returns the binary exchange key derived from the latest accepted token. */
    public function getExchangeKey() {
        return $this->exchangeKey;
    }

    /** Encrypts text or binary data into IV | GCM tag | ciphertext. */
    public function encrypt($string, $key = null) {
        return $this->seal(
            (string) $string,
            $this->dataAad(),
            'data',
            $key === null ? $this->key : (string) $key
        );
    }

    /** Decrypts and authenticates data produced by encrypt(). */
    public function decrypt($string, $key = null) {
        return $this->open(
            (string) $string,
            $this->dataAad(),
            'data',
            $key === null ? $this->key : (string) $key
        );
    }

    /**
     * Creates an opaque token: plain, timed, or refreshable.
     * tokenCreate(false, 900) expires after 900s; tokenCreate(true, 60, 86400)
     * refreshes 60s tokens until the 86400s maximum validity window ends.
     */
    public function tokenCreate($refreshable = false, $tokenLifetime = null, $maxTokenLifetime = null) {
        $refreshable = (bool) $refreshable;
        $hasTokenLifetime = !($tokenLifetime === null || $tokenLifetime === '');
        $timed = $refreshable || $hasTokenLifetime;
        $tokenLifetime = $timed ? $this->normalizeTokenLifetime($tokenLifetime) : 0;
        $maxTokenLifetime = $timed
            ? ($refreshable ? $this->normalizeMaxTokenLifetime($maxTokenLifetime) : $tokenLifetime)
            : 0;
        $validUntil = $timed ? $this->safeFutureTimestamp($maxTokenLifetime) : 0;
        $expiresAt = $timed ? min($this->safeFutureTimestamp($tokenLifetime), $validUntil) : 0;

        $token = $this->buildToken($timed, $tokenLifetime, $expiresAt, $validUntil, 0);
        $this->exchangeKey = $this->deriveFrameKey('exchange', hex2bin($token));

        return $token;
    }

    /** Validates a token and derives exchangeKey from the accepted frame. */
    public function checkToken($string, $tolerance = 0) {
        $this->exchangeKey = '';

        $decoded = $this->decodeToken($string);
        if ($decoded === false) {
            return false;
        }

        $tolerance = $this->normalizeTolerance($tolerance);

        if ($decoded['timed'] && !$this->payloadIsCurrent($decoded['payload'], $tolerance)) {
            return false;
        }

        $this->exchangeKey = $this->deriveFrameKey('exchange', $decoded['frame']);
        return true;
    }

    /**
     * Returns a replacement timed token without extending valid_until.
     * exchangeKey remains derived from the token accepted for this request.
     */
    public function tokenRefresh($string, $tolerance = 0) {
        $tolerance = $this->normalizeTolerance($tolerance);
        $decoded = $this->decodeToken($string);
        if ($decoded === false || !$decoded['timed']) {
            return false;
        }

        $payload = $decoded['payload'];
        $validUntil = $this->payloadValidUntil($payload);
        if (!$this->payloadIsCurrent($payload, $tolerance) || $validUntil < time()) {
            return false;
        }

        $acceptedExchangeKey = $this->deriveFrameKey('exchange', $decoded['frame']);
        $tokenLifetime = $this->payloadTokenLifetime($payload);
        $expiresAt = min($this->safeFutureTimestamp($tokenLifetime), $validUntil);
        $counter = min(0xffffffff, $this->payloadCounter($payload) + 1);

        $token = $this->buildToken(true, $tokenLifetime, $expiresAt, $validUntil, $counter);
        $this->exchangeKey = $acceptedExchangeKey;

        return $token;
    }

    private function normalizeKey($key) {
        if ($key === null || $key === '') {
            return random_bytes(self::MIN_KEY_BYTES);
        }

        $key = (string) $key;

        if (strlen($key) < self::MIN_KEY_BYTES) {
            trigger_error('SecureTokenizer key should contain at least 32 bytes of secret material.', E_USER_WARNING);
        }

        return $key;
    }

    private function normalizeTokenLifetime($tokenLifetime) {
        if ($tokenLifetime === null || $tokenLifetime === '') {
            $tokenLifetime = $this->defaultTokenLifetime === null || $this->defaultTokenLifetime === ''
                ? self::DEFAULT_TOKEN_LIFETIME_SECONDS
                : $this->defaultTokenLifetime;
        }

        $tokenLifetime = (int) $tokenLifetime;

        return max(self::MIN_TOKEN_LIFETIME_SECONDS, min(self::MAX_TOKEN_LIFETIME_SECONDS, $tokenLifetime));
    }

    private function normalizeMaxTokenLifetime($maxTokenLifetime) {
        if ($maxTokenLifetime === null || $maxTokenLifetime === '') {
            $maxTokenLifetime = $this->defaultMaxTokenLifetime === null || $this->defaultMaxTokenLifetime === ''
                ? self::DEFAULT_MAX_TOKEN_LIFETIME_SECONDS
                : $this->defaultMaxTokenLifetime;
        }

        $maxTokenLifetime = (int) $maxTokenLifetime;

        return max(self::MIN_MAX_TOKEN_LIFETIME_SECONDS, min(self::MAX_MAX_TOKEN_LIFETIME_SECONDS, $maxTokenLifetime));
    }

    private function normalizeTolerance($tolerance) {
        return max(0, min(self::MAX_TOLERANCE_SECONDS, (int) $tolerance));
    }

    private function safeFutureTimestamp($seconds) {
        $timestamp = time() + max(0, (int) $seconds);

        return $timestamp > 0xffffffff ? 0xffffffff : $timestamp;
    }

    private function assertOpenSslGcm() {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('OpenSSL extension is required.');
        }

        if (!in_array(self::CIPHER, openssl_get_cipher_methods(), true)) {
            throw new RuntimeException('OpenSSL AES-256-GCM support is required.');
        }
    }

    private function deriveKey($purpose, $keyMaterial = null) {
        $keyMaterial = $keyMaterial === null ? $this->key : (string) $keyMaterial;

        return $this->hkdf($keyMaterial, 32, 'SecureTokenizer v7 ' . $purpose, $this->contextFingerprintBinary());
    }

    private function deriveFrameKey($purpose, $frame) {
        $salt = hash('sha256', $frame . "\0" . $this->contextFingerprintBinary(), true);

        return $this->hkdf($this->key, 32, 'SecureTokenizer v7 frame ' . $purpose, $salt);
    }

    private function hkdf($ikm, $length, $info, $salt) {
        return hash_hkdf('sha256', (string) $ikm, (int) $length, (string) $info, (string) $salt);
    }

    /** Seals plaintext with AES-GCM and purpose-specific AAD. */
    private function seal($plainText, $aad, $purpose, $keyMaterial) {
        $iv = random_bytes(self::IV_BYTES);
        $tag = '';
        $key = $this->deriveKey($purpose, $keyMaterial);

        $cipherText = openssl_encrypt(
            $plainText,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
            self::TAG_BYTES
        );

        if (!is_string($cipherText) || !is_string($tag) || strlen($tag) !== self::TAG_BYTES) {
            throw new RuntimeException('OpenSSL encryption failed.');
        }

        return $iv . $tag . $cipherText;
    }

    /** Opens an AES-GCM frame and returns false when authentication fails. */
    private function open($frame, $aad, $purpose, $keyMaterial) {
        if (!is_string($frame) || strlen($frame) < self::IV_BYTES + self::TAG_BYTES) {
            return false;
        }

        $offset = 0;
        $iv = substr($frame, $offset, self::IV_BYTES);
        $offset += self::IV_BYTES;
        $tag = substr($frame, $offset, self::TAG_BYTES);
        $offset += self::TAG_BYTES;
        $cipherText = substr($frame, $offset);
        $key = $this->deriveKey($purpose, $keyMaterial);

        $plainText = openssl_decrypt(
            $cipherText,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );

        return is_string($plainText) ? $plainText : false;
    }

    private function buildToken($timed, $tokenLifetime, $expiresAt, $validUntil, $counter) {
        $payload = $this->encodeTokenPayload($timed, $tokenLifetime, $expiresAt, $validUntil, $counter);
        $frame = $this->seal($payload, $this->tokenAad(), 'token', $this->key);

        return bin2hex($frame);
    }

    private function encodeTokenPayload($timed, $tokenLifetime, $expiresAt, $validUntil, $counter) {
        if ((bool) $timed) {
            return pack(
                'CCNNNN',
                self::FORMAT_VERSION,
                self::TOKEN_FLAGS_TIMED,
                (int) $tokenLifetime,
                (int) $expiresAt,
                (int) $validUntil,
                (int) $counter
            );
        }

        return pack('CC', self::FORMAT_VERSION, self::TOKEN_FLAGS_PLAIN) . random_bytes(self::TOKEN_PAYLOAD_BYTES - 2);
    }

    private function payloadIsValid($payload) {
        if (!is_string($payload) || strlen($payload) !== self::TOKEN_PAYLOAD_BYTES) {
            return false;
        }

        $version = ord($payload[0]);
        $flags = ord($payload[1]);
        if ($version !== self::FORMAT_VERSION) {
            return false;
        }

        if ($flags === self::TOKEN_FLAGS_TIMED) {
            $tokenLifetime = $this->payloadTokenLifetime($payload);
            $expiresAt = $this->payloadExpiration($payload);
            $validUntil = $this->payloadValidUntil($payload);

            return $tokenLifetime >= self::MIN_TOKEN_LIFETIME_SECONDS
                && $tokenLifetime <= self::MAX_TOKEN_LIFETIME_SECONDS
                && $expiresAt > 0
                && $validUntil > 0
                && $expiresAt <= $validUntil;
        }

        return $flags === self::TOKEN_FLAGS_PLAIN;
    }

    private function payloadIsTimed($payload) {
        return is_string($payload)
            && strlen($payload) === self::TOKEN_PAYLOAD_BYTES
            && ord($payload[1]) === self::TOKEN_FLAGS_TIMED;
    }

    private function payloadTokenLifetime($payload) {
        $unpacked = unpack('NtokenLifetime', substr($payload, 2, 4));

        return is_array($unpacked) ? (int) $unpacked['tokenLifetime'] : 0;
    }

    private function payloadExpiration($payload) {
        $unpacked = unpack('NexpiresAt', substr($payload, 6, 4));

        return is_array($unpacked) ? (int) $unpacked['expiresAt'] : 0;
    }

    private function payloadValidUntil($payload) {
        $unpacked = unpack('NvalidUntil', substr($payload, 10, 4));

        return is_array($unpacked) ? (int) $unpacked['validUntil'] : 0;
    }

    private function payloadCounter($payload) {
        $unpacked = unpack('Ncounter', substr($payload, 14, 4));

        return is_array($unpacked) ? (int) $unpacked['counter'] : 0;
    }

    private function payloadIsCurrent($payload, $tolerance = 0) {
        return $this->payloadExpiration($payload) >= time() - max(0, (int) $tolerance);
    }

    private function decodeToken($token) {
        $parsed = $this->parseToken($token);
        if ($parsed === false) {
            return false;
        }

        $payload = $this->open($parsed['frame'], $this->tokenAad(), 'token', $this->key);
        if (!is_string($payload) || !$this->payloadIsValid($payload)) {
            return false;
        }

        $parsed['timed'] = $this->payloadIsTimed($payload);
        $parsed['payload'] = $payload;
        return $parsed;
    }

    /** Parses only the fixed hex envelope; the token type is encrypted. */
    private function parseToken($token) {
        $binary = $this->hexToBinary($token);
        if ($binary === false) {
            return false;
        }

        $frameLength = self::IV_BYTES + self::TAG_BYTES + self::TOKEN_PAYLOAD_BYTES;
        if (strlen($binary) !== $frameLength) {
            return false;
        }

        return ['frame' => $binary];
    }

    private function tokenAad() {
        return 'SecureTokenizer|token|v7|' . $this->contextFingerprint();
    }

    private function dataAad() {
        return 'SecureTokenizer|data|v7|' . $this->contextFingerprint();
    }

    private function contextFingerprint() {
        return bin2hex($this->contextFingerprintBinary());
    }

    /** Builds the bound context used by both AES-GCM AAD and HKDF. */
    private function contextFingerprintBinary() {
        $parts = ['SecureTokenizer v7'];

        $parts[] = $this->ssb ? 'ssb:' . $this->serverAddress : 'ssb:off';
        $parts[] = $this->scb ? 'scb:' . $this->clientAddress : 'scb:off';

        return hash('sha256', implode("\0", $parts), true);
    }

    private function hexToBinary($value) {
        if (!is_string($value)) {
            return false;
        }

        $value = trim($value);
        if ($value === '' || (strlen($value) % 2) !== 0 || !ctype_xdigit($value)) {
            return false;
        }

        return hex2bin($value);
    }
}
