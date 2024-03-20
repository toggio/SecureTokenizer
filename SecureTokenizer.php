<?php
/*
 * Secure Tokenizer Class (SecureTokenizer) v1.0.1
 *
 * A PHP Library for Cryptographically Secure Token Generation and Management 
 *
 * SecureTokenizer is a sophisticated PHP library designed
 * to enhance web application security by providing advanced
 * capabilities for generating and managing secure tokens.
 * This library integrates seamlessly into PHP/AJAX projects,
 * offering a robust solution for creating unpredictable,
 * cryptographically secure tokens suitable for authentication,
 * session management, attack prevention, encryption tasks, and more.
 *
 * Copyright (C) 2024 under GPL v. 2 license
 * 12 March 2024
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

// Class for pseduorandom number generation
class pseudoRandom {

	// Initialize variable and constant for random number generation
	private static $savedRSeed;
	private static $RSeed = 0;		
	private static $a = 1664525;
	private static $c = 1013904223;
    private static $m = 4294967296; // 2^32
	private static $counter = 0;
	
	// Init the class
	public function __construct($seed = NULL) {
		// Check the seed. If is string use crc32. If no seed given, use current time
		if (is_string($seed)) {
			self::$RSeed=crc32($seed);
		} elseif ($seed != NULL) {
			self::$RSeed = abs(intval($seed));
		} else {
			self::$RSeed = time();
		}
		self::$counter = 0;
		self::$c = 1013904223;
	}
	
	// Function for changing (and resetting) seed
	public function reSeed($seed = NULL) {
		self::__construct($seed);
	}
	
	// Save current status
    public function saveStatus() {
        self::$savedRSeed = self::$RSeed;
    }

    // Restore saved status
    public function restoreStatus() {
        if (self::$savedRSeed !== null) {
            self::$RSeed = self::$savedRSeed;
        }
    }
	
	// Generate (pseudo) random integer
	public function randInt($min = 0, $max = 255) {
		self::$c = crc32(self::$counter. self::$RSeed . self::$counter);
		self::$RSeed = (self::$RSeed * self::$a + self::$c) % self::$m;
		self::$counter += 1;
		return (int)floor((self::$RSeed / self::$m) * ($max - $min + 1) + $min);
	}
	
	// Generate (pseudo) random bytes
	public function randBytes($len = 1, $decimal=false, $readable = false) {
		$char = '';
		if ($decimal) $char = Array();
		for ($i=0; $i<$len; $i++) {
			if ($readable) $n = $this->randInt(32,126); else $n = $this->randInt();
			if (!$decimal) $char.= chr($n); else $char[]=$n;
		}
		return $char;
    }
}

// Class for secure token generation, check, and management
class secureTokenizer {
	
	private $random;
	public $nonce;
	public $key;
	private $md5Key1;
	private $md5Key2;
	public $jsToken;
	public $tbrToken;
	private $length;
	private $remote_addr = "127.0.0.1";
	private $server_addr = "127.0.0.1";
	
	// Initialize class. If no key given, use timebased key
	public function __construct($key = NULL, $xss=true) {
		if ($key) $this->key = $key; else $this->key = floor(time()/3600);
				
		// If XSS enabled, get remote_addr e server_addr in order to add them later to encryption key
		if ( (isset($_SERVER['REMOTE_ADDR'])) && (isset($_SERVER['SERVER_ADDR'])) && ($xss) ) {
			$this->remote_addr = $_SERVER['REMOTE_ADDR'];
			$this->server_addr = $_SERVER['SERVER_ADDR'];
		}
		// Nonce and lstoken lenght in bytes (so 32bytes = 256bit)
		$this->length = 32;
		$this->random = new pseudoRandom($key);		
	}
	
	// Change encryption/generation key
	public function changeKey($key) {
		$this->key = $key;
	}
	
	// Restart the class
    private function restart($s = NULL) {
		$this->__construct($s = NULL);
	}
    
	// Create second part (less significant) token The token is pseudocasual, but based on nonce (that is "true" casual)
	public function lsTokenCreate() {
		$key = $this->key;
		$length = $this->length;
		$this->random->saveStatus();
		$this->random->reSeed($this->server_addr.$this->nonce.$this->remote_addr);
		
		// Pseduo-casual generator (seeded by key)
		$lsToken = $this->random->randBytes($length);
		
		// Pseudo casual lsToken swapping and shuffling based on nonce
		$lsToken = $this->shuffleString($lsToken,md5($this->nonce.$this->remote_addr),true);
		$lsToken = $this->xorString($lsToken,hash('ripemd128',strrev($this->server_addr.$this->nonce)),true);
		
		$this->random->restoreStatus();
		
		return $lsToken;
	}
	
	// Create time-based token
	public function tbTokenCreate($validity = 3, $offset = 0) {
		$key = $this->key;
		$length = $this->length;
		
		// Time based token is calculated on time and change every $validity seconds
		$time = (string)floor((time()-0.1+$offset+15)/$validity);
		
		// In order to obfuscate nonce and key to javascript code and prevent attacks from different IP the two base-keys are sha256 hashed along with nonce, key, remote ip and server ip
		$md5Key1 = hash('sha256',$this->nonce.$this->key.$this->remote_addr);
		$md5Key2 = hash('sha256',$this->server_addr.$this->key.$this->nonce);
		
		// The tbrtoken is calculated appending $time to the hashed key created before, and again hasehd (this time with md5 alg, that is more easy to calculate in js)
		$tbToken = md5($md5Key1.$time).md5($time.$md5Key2);
		// $tbrToken = $md5Key;
		return hex2bin($tbToken);
	}
	
	// XOR function based on key. The string is xored also with a pseduorandom offset
	private function xorString($string, $key, $enc) {
		$result = '';
		$len = strlen($string);
		
		$this->random->saveStatus();
		$this->random->reSeed($key);
		
		
		for ($i = 0; $i < $len; $i++) {
			$offset = $this->random->randInt(1,254);
			$char = ord($string[$i]);
			
			if ($enc) {
				// If encoding, apply offset befor xoring
				$char = ($char + $offset) % 256;
			}

			// Apply XOR with key char
			$xoredChar = $char ^ ord($key[$i % strlen($key)]);

			if (!$enc) {
				// If decoding remove offset after xoring
				$xoredChar = ($xoredChar - $offset + 256) % 256;
			}

			$result .= chr($xoredChar);
		}
		$this->random->restoreStatus();
		return $result;
	}
	
	// Shuffle function based on key. Chars are permuted on pseudorandom order
	private function shuffleString($string, $key, $enc) {
		$len = strlen($string);
		
		$this->random->saveStatus();
		$this->random->reSeed($key);
			
		$swapPairs = [];

		// Generate swap array in advance
		for ($i = 0; $i < floor($len / 2); $i++) {
			$first = $this->random->randInt(0, $len - 1);
			$second = $this->random->randInt(0, $len - 1);
			$swapPairs[] = [$first, $second];
		}

		// If decoding invert swap order
		if (!$enc) {
			// Per la decifratura, inverti l'ordine degli scambi
			$swapPairs = array_reverse($swapPairs);
		}

		// Apply the shuffle
		foreach ($swapPairs as $pair) {
			list($first, $second) = $pair;
			$temp = $string[$first];
			$string[$first] = $string[$second];
			$string[$second] = $temp;
		}
		
		$this->random->restoreStatus();
		return $string;
	}

	// Strong encryption function - The string is encoded with XOR and SHUFFLE functions and then encrypted with AES-256-CFB algo
	public function encrypt($string, $key=NULL) {
		if (!$key) $key = $this->key;
		
		$this->random->saveStatus();
		
		// Seed the PRNG with key and client ip address
		$this->random->reSeed($this->server_addr.$key.$this->remote_addr);
		
		$ivlen = openssl_cipher_iv_length("aes-256-cfb");		
		
		// Pseudorandom iv (based on key)
		$iv = $this->random->randBytes($ivlen);
		$iv2 = $this->random->randBytes($ivlen);
		
		$key2 = $this->random->randBytes($ivlen);
		
		// Obufscating (not secure) part of encryption
		$string = $this->xorString($string,$key,true);
		$string = $this->shuffleString($string,strrev($key),true);
		$string = $this->xorString($string,strrev($key),true);
		$string = $this->shuffleString($string,$key,true);
		
		// Secure encrypt - the key is reversed and appended to the client ip address
		$string = openssl_encrypt($string,"aes-256-cfb",$this->server_addr.strrev($key).$this->remote_addr,OPENSSL_RAW_DATA,$iv);
		$string = openssl_encrypt($string,"aes-256-ofb",$key2,OPENSSL_RAW_DATA,$iv2);

		$this->random->restoreStatus();
		return $string;
	}

	// Strong decryption function - The string is decrypted with AES-256-CFB algo and then decoded with XOR and SHUFFLE functions
	public function decrypt($string, $key=NULL) {
		if (!$key) $key = $this->key;
		
		$this->random->saveStatus();
		
		// Seed the PRNG with key and client ip address
		$this->random->reSeed($this->server_addr.$key.$this->remote_addr);
		
		$ivlen = openssl_cipher_iv_length("aes-256-cfb");
		
		// Pseudorandom iv (based on key)
		$iv = $this->random->randBytes($ivlen);
		$iv2 = $this->random->randBytes($ivlen);
		
		$key2 = $this->random->randBytes($ivlen);
		
		// Secure decrypt
		$string = openssl_decrypt($string,"aes-256-ofb",$key2,OPENSSL_RAW_DATA,$iv2);
		$string = openssl_decrypt($string,"aes-256-cfb",$this->server_addr.strrev($key).$this->remote_addr,OPENSSL_RAW_DATA,$iv);
			
		// Decode string
		$string = $this->shuffleString($string,$key,false);
		$string = $this->xorString($string,strrev($key),false);
		$string = $this->shuffleString($string,strrev($key),false);
		$string = $this->xorString($string,$key,false);
	
		$this->random->restoreStatus();
		return $string;
	}		
	
	// Secure Token Creation
	public function tokenCreate($timeBased = false, $validity=3, $jsVar = "token") {
		$key = $this->key;
		$length = $this->length;
		
		$this->random->saveStatus();
		$this->random->reSeed($key);
		
		// This is the most cryptographically important part of the class - A crypto-secure random key (nonce) is created
		$this->nonce = random_bytes($length/2) . openssl_random_pseudo_bytes($length/2);
		// $this->nonce = "1234567890abcdef"; // For debug purpose
		
		// lsToken creation - this is pseudorandom but it will be encrypted with nonce
		$lsToken = $this->lsTokenCreate($key,$length);
		
		// Token creation: the first half part is the nonce securely encrypted with main key, while the second part is the lsToken encrypted with nonce as the key
		$result = bin2hex($this->encrypt($this->nonce, $key) . $this->encrypt($lsToken,$this->nonce));
		
		// The result is shuffled for better offuscating
		$result = $this->shuffleString($result,strrev($key),true);
		$this->random->restoreStatus();
		
		// If the token is time-based, include time-based part
		if (!$timeBased) $this->jsToken = "let $jsVar='$result';\n"; else {
			$this->md5Key1 = hash('sha256',$this->nonce.$this->key.$this->remote_addr);
			$this->md5Key2 = hash('sha256',$this->server_addr.$this->key.$this->nonce);
			$this->jsToken = "let $jsVar='$result' + MD5('$this->md5Key1' + (Math.floor(((Date.now()+15000)/1000)/$validity)).toString()) + MD5((Math.floor(((Date.now()+15000)/1000)/$validity)).toString()+'$this->md5Key2');\n";	
			$result.=bin2hex($this->tbTokenCreate($validity));		
		}
		return $result;
	}
	
	// Token decrypting - This function return lsToken and save nonce and tbrToken in their public vars
	public function tokenDecrypt($string, $timeBased = false) {
		$key = $this->key;
		$length = $this->length;
		
		$this->random->saveStatus();
		$this->random->reSeed($key);
		
		// If time-based token, extact tb part and save in public $tbrToken variable
		if ($timeBased) {
			$partLength = ceil(strlen($string) / 3);
			$this->tbrToken = hex2bin(substr($string, $length *4));
			$string = substr($string, 0, $length *4);
			// $secondPart = substr($string, $partLength, $partLength);
		}
		
		// Decode token
		$string = $this->shuffleString($string,strrev($key),false);
		
		// Extract encryped nonce and lstoken
		$middle = ceil(strlen($string) / 2);
		$firstPart = substr($string, 0, $middle);
		$secondPart = substr($string, $middle);
		
		// Decrypt nonce and lstoken
		$this->nonce = $this->decrypt(hex2bin($firstPart),$key);
		$lsToken = $this->decrypt(hex2bin($secondPart),$this->nonce);

		$this->random->restoreStatus();
		return $lsToken;
	}
	
	// Token checking - return true or false
	public function checkToken($string, $timeBased = false, $validity = 3, $tolerance = 1) {
		$key = $this->key;
		$length = $this->length;
		
		$lsToken = $this->tokenDecrypt($string, $timeBased);
		$myLsToken = $this->lsTokenCreate();
		
		if ($timeBased) {
			$myCurrentTbToken = $this->tbTokenCreate($validity,0);
			$myPastTbToken = $this->tbTokenCreate($validity, -$tolerance);
			$myFutureTbToken = $this->tbTokenCreate($validity ,$tolerance);
		} else $myCurrentTbToken = $this->tbrToken;
			
		// echo bin2hex($myCurrentTbToken) . "." . bin2hex($this->tbrToken) ."\n";
		return ($lsToken === $myLsToken) && ($this->tbrToken === $myCurrentTbToken || $this->tbrToken === $myPastTbToken || $this->tbrToken === $myFutureTbToken);
	}
	
// Public variabile with javascript code for md5 calculation
public $jsInit = <<< JSINIT
<script>
var MD5 = function(d){var r = M(V(Y(X(d),8*d.length)));return r.toLowerCase()};function M(d){for(var _,m="0123456789ABCDEF",f="",r=0;r<d.length;r++)_=d.charCodeAt(r),f+=m.charAt(_>>>4&15)+m.charAt(15&_);return f}function X(d){for(var _=Array(d.length>>2),m=0;m<_.length;m++)_[m]=0;for(m=0;m<8*d.length;m+=8)_[m>>5]|=(255&d.charCodeAt(m/8))<<m%32;return _}function V(d){for(var _="",m=0;m<32*d.length;m+=8)_+=String.fromCharCode(d[m>>5]>>>m%32&255);return _}function Y(d,_){d[_>>5]|=128<<_%32,d[14+(_+64>>>9<<4)]=_;for(var m=1732584193,f=-271733879,r=-1732584194,i=271733878,n=0;n<d.length;n+=16){var h=m,t=f,g=r,e=i;f=md5_ii(f=md5_ii(f=md5_ii(f=md5_ii(f=md5_hh(f=md5_hh(f=md5_hh(f=md5_hh(f=md5_gg(f=md5_gg(f=md5_gg(f=md5_gg(f=md5_ff(f=md5_ff(f=md5_ff(f=md5_ff(f,r=md5_ff(r,i=md5_ff(i,m=md5_ff(m,f,r,i,d[n+0],7,-680876936),f,r,d[n+1],12,-389564586),m,f,d[n+2],17,606105819),i,m,d[n+3],22,-1044525330),r=md5_ff(r,i=md5_ff(i,m=md5_ff(m,f,r,i,d[n+4],7,-176418897),f,r,d[n+5],12,1200080426),m,f,d[n+6],17,-1473231341),i,m,d[n+7],22,-45705983),r=md5_ff(r,i=md5_ff(i,m=md5_ff(m,f,r,i,d[n+8],7,1770035416),f,r,d[n+9],12,-1958414417),m,f,d[n+10],17,-42063),i,m,d[n+11],22,-1990404162),r=md5_ff(r,i=md5_ff(i,m=md5_ff(m,f,r,i,d[n+12],7,1804603682),f,r,d[n+13],12,-40341101),m,f,d[n+14],17,-1502002290),i,m,d[n+15],22,1236535329),r=md5_gg(r,i=md5_gg(i,m=md5_gg(m,f,r,i,d[n+1],5,-165796510),f,r,d[n+6],9,-1069501632),m,f,d[n+11],14,643717713),i,m,d[n+0],20,-373897302),r=md5_gg(r,i=md5_gg(i,m=md5_gg(m,f,r,i,d[n+5],5,-701558691),f,r,d[n+10],9,38016083),m,f,d[n+15],14,-660478335),i,m,d[n+4],20,-405537848),r=md5_gg(r,i=md5_gg(i,m=md5_gg(m,f,r,i,d[n+9],5,568446438),f,r,d[n+14],9,-1019803690),m,f,d[n+3],14,-187363961),i,m,d[n+8],20,1163531501),r=md5_gg(r,i=md5_gg(i,m=md5_gg(m,f,r,i,d[n+13],5,-1444681467),f,r,d[n+2],9,-51403784),m,f,d[n+7],14,1735328473),i,m,d[n+12],20,-1926607734),r=md5_hh(r,i=md5_hh(i,m=md5_hh(m,f,r,i,d[n+5],4,-378558),f,r,d[n+8],11,-2022574463),m,f,d[n+11],16,1839030562),i,m,d[n+14],23,-35309556),r=md5_hh(r,i=md5_hh(i,m=md5_hh(m,f,r,i,d[n+1],4,-1530992060),f,r,d[n+4],11,1272893353),m,f,d[n+7],16,-155497632),i,m,d[n+10],23,-1094730640),r=md5_hh(r,i=md5_hh(i,m=md5_hh(m,f,r,i,d[n+13],4,681279174),f,r,d[n+0],11,-358537222),m,f,d[n+3],16,-722521979),i,m,d[n+6],23,76029189),r=md5_hh(r,i=md5_hh(i,m=md5_hh(m,f,r,i,d[n+9],4,-640364487),f,r,d[n+12],11,-421815835),m,f,d[n+15],16,530742520),i,m,d[n+2],23,-995338651),r=md5_ii(r,i=md5_ii(i,m=md5_ii(m,f,r,i,d[n+0],6,-198630844),f,r,d[n+7],10,1126891415),m,f,d[n+14],15,-1416354905),i,m,d[n+5],21,-57434055),r=md5_ii(r,i=md5_ii(i,m=md5_ii(m,f,r,i,d[n+12],6,1700485571),f,r,d[n+3],10,-1894986606),m,f,d[n+10],15,-1051523),i,m,d[n+1],21,-2054922799),r=md5_ii(r,i=md5_ii(i,m=md5_ii(m,f,r,i,d[n+8],6,1873313359),f,r,d[n+15],10,-30611744),m,f,d[n+6],15,-1560198380),i,m,d[n+13],21,1309151649),r=md5_ii(r,i=md5_ii(i,m=md5_ii(m,f,r,i,d[n+4],6,-145523070),f,r,d[n+11],10,-1120210379),m,f,d[n+2],15,718787259),i,m,d[n+9],21,-343485551),m=safe_add(m,h),f=safe_add(f,t),r=safe_add(r,g),i=safe_add(i,e)}return Array(m,f,r,i)}function md5_cmn(d,_,m,f,r,i){return safe_add(bit_rol(safe_add(safe_add(_,d),safe_add(f,i)),r),m)}function md5_ff(d,_,m,f,r,i,n){return md5_cmn(_&m|~_&f,d,_,r,i,n)}function md5_gg(d,_,m,f,r,i,n){return md5_cmn(_&f|m&~f,d,_,r,i,n)}function md5_hh(d,_,m,f,r,i,n){return md5_cmn(_^m^f,d,_,r,i,n)}function md5_ii(d,_,m,f,r,i,n){return md5_cmn(m^(_|~f),d,_,r,i,n)}function safe_add(d,_){var m=(65535&d)+(65535&_);return(d>>16)+(_>>16)+(m>>16)<<16|65535&m}function bit_rol(d,_){return d<<_|d>>>32-_}
</script>

JSINIT;
}
?>
