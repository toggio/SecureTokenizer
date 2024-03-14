<?php
require("SecureTokenizer.php");

$key = 'A strong key 12345!';
$tokenizer = new secureTokenizer($key);

$secureToken = $tokenizer->tokenCreate(true,10);

echo $tokenizer->jsInit; // Print the JavaScript code for creating time-based tokens
?>

<script>
    function myAjaxFunction() {
        // Prints "let var token=...;" - Code for generating JS time-based token
        <?php echo $tokenizer->jsToken; ?>
        fetch('receiver.php?token='+token)
          .then(response => response.text()) 
          .then(text => document.write(text)) 
          .catch(error => console.error('Fetch error:', error));
    }
    myAjaxFunction();
</script>
