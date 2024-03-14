<?php
require_once 'SecureTokenizer.php';

$key = 'A strong key 12345!';
$tokenizer = new secureTokenizer($key);

// Simple token generation
$secureToken = $tokenizer->tokenCreate();
echo "<b>Simple Token generation</b><br>\n";
echo "Secure Token: $secureToken<br>\n"; // Outputs the generated secure token

$jsToken = $tokenizer->jsToken;
echo "JavaScript code: $jsToken<br>\n"; // Outputs the generated JavaScript code

$decryptedToken = bin2hex($tokenizer->tokenDecrypt($secureToken));
echo "Decrypted lsToken: $decryptedToken<br>\n"; // Outputs the decrypted content of the token

$nonce = bin2hex($tokenizer->nonce);
echo "Decrypted nonce: $nonce<br>\n"; // Outputs the decrypted nonce

$isTokenValid = $tokenizer->checkToken($secureToken);
if ($isTokenValid) {
    echo "Token is valid.<br>\n";
} else {
    echo "Token is invalid.<br>\n";
}

// Time based token generation
$secureToken = $tokenizer->tokenCreate(true);
echo "<br><b>Time-based Token generation</b><br>\n";
echo "Secure Token: $secureToken<br>\n"; // Outputs the generated secure token

$jsToken = $tokenizer->jsToken;
echo "JavaScript code: $jsToken<br>\n"; // Outputs the generated JavaScript code

$decryptedToken = bin2hex($tokenizer->tokenDecrypt($secureToken,true));
echo "Decrypted lsToken: $decryptedToken<br>\n"; // Outputs the decrypted content of the token

$nonce = bin2hex($tokenizer->nonce);
echo "Decrypted nonce: $nonce<br>\n"; // Outputs the decrypted nonce

$isTokenValid = $tokenizer->checkToken($secureToken,true);
if ($isTokenValid) {
    echo "Token is valid.<br>\n";
} else {
    echo "Token is invalid.<br>\n";
}
?>
