<?php
require("SecureTokenizer.php");

$key = 'A strong key 12345!';
$tokenizer = new secureTokenizer($key);

// The token you get (for example via Ajax request)
if (isset($_GET["token"])) $secureToken = $_GET["token"]; else $secureToken = bin2hex(random_bytes(32));

$isTokenValid = $tokenizer->checkToken($secureToken,true,10);
if ($isTokenValid) {
    echo "Token is valid.";
} else {
    echo "Token is invalid.";
}
?>
