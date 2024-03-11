# SecureTokenizer
A PHP Library for Cryptographically Secure Token Generation and Management

SecureTokenizer is a powerful PHP library designed to enhance the security of web applications. It achieves this by providing advanced capabilities for generating and managing secure tokens. This library is perfect for integrating into PHP and AJAX projects, offering developers a robust solution for creating unpredictable, cryptographically secure tokens. These tokens are ideal for a variety of purposes, including authentication, session management, attack prevention, encryption tasks, and more.

## Features

- **Cryptographically Secure Token Generation**: Leverages both PHP's `random_bytes` and OpenSSL's `openssl_random_pseudo_bytes` to achieve high entropy in token generation, ensuring each token is unique and unpredictable.
- **Advanced Encryption and Decryption**:  Implements AES-256 for encryption and SHA-256 for hashing, making the tokens cryptographically secure and virtually invulnerable to attacks.
- **Javascript integration**: SecureTokenizer includes JavaScript code for MD5 calculation, enabling client-side time-based token generation. This facilitates seamless integration of secure token handling across client and server boundaries.
- **Time-Based Token Generation**: Offers the capability to generate time-based tokens with customizable durations, ensuring token validity only within a specific timeframe and enhancing security for time-sensitive operations.
- **Flexibility and Security**: Designed to be easy and flexible for developers to integrate, while ensuring the highest level of security to protect against modern web threats.

## Installation

Simply include SecureTokenizer in your project to start generating secure tokens:

```php
require_once 'path/to/SecureTokenizer.php';
```

## Quick Start Guide

### Generating a Secure Token
```php
$key = 'A strong key 12345';
$tokenizer = new secureTokenizer($key);

$secureToken = $tokenizer->tokenCreate();
echo $secureToken; // Outputs the generated secure token
```

### Decrypting a Token
```php
$key = 'A strong key 12345';
$tokenizer = new secureTokenizer($key);

// The token you get (for example via Ajax call)
$secureToken = 'a05f970fe2732a77d57a7f784b050fca2f4ed5314e15dada4f0ab0dc24889318';

$decryptedToken = $tokenizer->tokenDecrypt($secureToken);
echo $decryptedToken; // Outputs the decrypted content of the token
```

### Verifying a Token
```php
$key = 'A strong key 12345';
$tokenizer = new secureTokenizer($key);

// The token you get (for example via Ajax call)
$secureToken = 'a05f970fe2732a77d57a7f784b050fca2f4ed5314e15dada4f0ab0dc24889318';

$isTokenValid = $tokenizer->checkToken($secureToken);
if ($isTokenValid) {
    echo "Token is valid.";
} else {
    echo "Token is invalid.";
}
```

## How It Works
SecureTokenizer combines cryptographically secure random key generation with a sophisticated algorithm that includes:

- Generating a nonce as a secure, encrypted main key, included in the first part of the token.
- Creating a psudo-randomly generator second part of the token (`lsToken`) that is encrypted using the nonce as key.
- For time-based tokens, ensures they are securely hashed (using SHA-256) for client-side (JavaScript) use, such as AJAX calls.
- Ensuring all tokens are obfuscated and securely encrypted using both XOR operations and AES-256-CFB encryption for maximum security.

## Customization and Advanced Usage
SecureTokenizer allows for detailed customization, including key changes, adjusting token length, and change time validity. For advanced usage and customization options, refer to the examples provided with the library.

## License
SecureTokenizer is licensed under the Apache License, Version 2.0. You are free to use, modify, and distribute the library in compliance with the license.

Copyright (C) 2024 Luca Soltoggio

https://www.lucasoltoggio.it/
