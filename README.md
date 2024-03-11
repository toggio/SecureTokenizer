# SecureTokenizer
A PHP Library for Cryptographically Secure Token Generation and Management

SecureTokenizer is a powerful PHP library designed to enhance the security of web applications. It achieves this by providing advanced capabilities for generating and managing secure tokens. This library is perfect for integrating into PHP and AJAX projects, offering developers a robust solution for creating unpredictable, cryptographically secure tokens. These tokens are ideal for a variety of purposes, including authentication, session management, attack prevention, encryption tasks, and more.

## Features

- **Cryptographically Secure Token Generation**: Leverages both PHP's `random_bytes` and OpenSSL's `openssl_random_pseudo_bytes` to achieve high entropy in token generation, ensuring each token is unique and unpredictable.
- **Advanced Encryption and Decryption**:  Implements AES-256 for encryption and utilizes SHA-256 for hashing related data, making the tokens and associated processes cryptographically secure and virtually invulnerable to attacks.
- **JavaScript integration**: SecureTokenizer includes JavaScript code dynamic creation, enabling client-side time-based token generation. This facilitates seamless integration of secure token handling across client and server boundaries.
- **Time-Based Token Generation**: Offers the capability to generate time-based tokens with customizable durations, limiting their validity to specific timeframes for enhanced security in time-sensitive operations.
- **Flexibility and Security**: Designed to be easy and flexible for developers to integrate, while ensuring the highest level of security to protect against modern web threats.

## Installation

Simply include SecureTokenizer in your project to start generating secure tokens:

```php
require_once 'path/to/SecureTokenizer.php';
```

## Quick Start Guide

### Generating a Secure Token
```php
$key = 'A strong key 12345!';
$tokenizer = new secureTokenizer($key);

$secureToken = $tokenizer->tokenCreate();
echo $secureToken; // Outputs the generated secure token
```

### Verifying a Token
```php
$key = 'A strong key 12345!';
$tokenizer = new secureTokenizer($key);

// The token you get (for example via Ajax request)
$secureToken = 'a05f970fe2732a77d57a7f784b050fca2f4ed5314e15dada4f0ab0dc24889318';

$isTokenValid = $tokenizer->checkToken($secureToken);
if ($isTokenValid) {
    echo "Token is valid.";
} else {
    echo "Token is invalid.";
}
```

### Generating a time-based token with repeated AJAX calls
**PHP CODE**
```php
$key = 'A strong key 12345!';
$tokenizer = new secureTokenizer($key);

$secureToken = $tokenizer->tokenCreate(true);

echo $tokenizer->jsInit; // Print the JavaScript code for creating time-based tokens
```
**HTML/JS CODE**
```html
<script>
    function myAjaxRepeatedFunction() {
        // Prints "let var token=...;" - Code for generating JS time-based token
        <?php echo $tokenizer->jsToken; ?>
        // The rest of my JavaScript function here
    }
</script>
```

## How It Works
SecureTokenizer combines cryptographically secure random key generation with a sophisticated algorithm that includes:

- Generating a strong encrypted cryptographycally secure random main key `$nonce`, included in the first part of the token.
- Creating a psudo-randomly generated second part of the token `$lsToken` that is encrypted using the nonce as key.
- For time-based tokens, ensuring they are securely hashed (using SHA-256) for client-side (JavaScript) use, such as AJAX calls.
- Ensuring all tokens are obfuscated and securely encrypted using both XOR operations and AES-256 encryption for maximum security.
- Checking validity of received tokens even with time-based check

## Customization and Advanced Usage
SecureTokenizer allows for detailed customization, including key changes and change time validity. For advanced usage and customization options, refer to the examples provided with the library and the next section explaining the various properties and methods of this class.

## Public properties and methods

### Properties

- `string (binary)` **$nonce**: The "nonce", a cryptographically secure random key used in token generation. This properties is very useful, because its value can be used for secure encrypting and decrypting datas between sender and receiver.
- `string` **$jsToken**: Initialization string for a JavaScript variable that includes the token code used for client-side Ajax requests.
- `string (binary)` **$tbrToken**: Time-Based Reference Token, used for validating time-sensitive tokens. This public property is useful for debugging purpose.
- `string` **$jsInit**: JavaScript code to include in your sender page containing functions for managing client-side (JavaScript) time-based token.

### Methods

- `string (hex)` **tokenCreate(bool $timeBased=false, int $validity=3, string $jsVar='token')**: Generates a secure token. If `$timeBased` is `true`, generates a time-based token with specified validity. Returns the encrypted token, and saves the string for initializating a Javascript variabile named `$jsvar` in the property `$jsToken`.
- `string (binary)` **tokenDecrypt(string $string, bool $timeBased=false)**: Decrypts a given token hex string. If the token is time-based, handles decryption accordingly. Saves the value of nonce in the `$nonce` property and of time-based received token in `$tbrToken` property. Returns `$lsToken`
- `bool` **checkToken(string $string, bool $timeBased=false, int $validity=3, int $tolerance=1)**: Validates a token against the generated reference. Checks time-based tokens with specified validity and tolerance. Returns `true` or `false`, and save nonce, and time-based token in their respective properties.
- `string (binary)` **encrypt(string $string, string $key=null)**: Encrypts a given string (such as a token, nonce, or even text or binary data) with the specified key or the default key if none is provided. Useful for sending encrypted data using `$nonce` or `$lsToken` as key.
- `string (binary)` **decrypt(string $string, string $key=null)**: Decrypts a given string (such as a token, nonce, or even text or binary data) with the specified key or the default key if none is provided. Useful for receiving encrypted data using `$nonce` or `$lsToken` as key.

## License
SecureTokenizer is licensed under the Apache License, Version 2.0. You are free to use, modify, and distribute the library in compliance with the license.

Copyright (C) 2024 Luca Soltoggio - https://www.lucasoltoggio.it/
