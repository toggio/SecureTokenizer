<?php
/*
 * Secure Tokenizer Class (SecureTokenizer) v1.0.3 - 22 March 2024
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
 * Copyright (C) 2024 under Apache License, Version 2.0
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
	private $shaKey1;
	private $shaKey2;
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
		$shaKey1 = hash('sha256',$this->nonce.$this->key.$this->remote_addr);
		$shaKey2 = hash('sha256',$this->server_addr.$this->key.$this->nonce);
		
		// The tbrtoken is calculated appending $time to the hashed key created before, and again hasehd (this time with md5 alg, that is more easy to calculate in js)
		$tbToken = hash('sha256',$shaKey1.$time.$shaKey2);
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
			$this->shaKey1 = hash('sha256',$this->nonce.$this->key.$this->remote_addr);
			$this->shaKey2 = hash('sha256',$this->server_addr.$this->key.$this->nonce);
			$this->jsToken = "let $jsVar='$result' + sha256('$this->shaKey1' + (Math.floor(((Date.now()+15000)/1000)/$validity)).toString() + '$this->shaKey2');\n";	
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
/**
 * [js-sha256]{@link https://github.com/emn178/js-sha256}
 *
 * @version 0.11.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2024
 * @license MIT
 */
!function(){"use strict";function t(t,i){i?(d[0]=d[16]=d[1]=d[2]=d[3]=d[4]=d[5]=d[6]=d[7]=d[8]=d[9]=d[10]=d[11]=d[12]=d[13]=d[14]=d[15]=0,this.blocks=d):this.blocks=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],t?(this.h0=3238371032,this.h1=914150663,this.h2=812702999,this.h3=4144912697,this.h4=4290775857,this.h5=1750603025,this.h6=1694076839,this.h7=3204075428):(this.h0=1779033703,this.h1=3144134277,this.h2=1013904242,this.h3=2773480762,this.h4=1359893119,this.h5=2600822924,this.h6=528734635,this.h7=1541459225),this.block=this.start=this.bytes=this.hBytes=0,this.finalized=this.hashed=!1,this.first=!0,this.is224=t}function i(i,r,s){var e,n=typeof i;if("string"===n){var o,a=[],u=i.length,c=0;for(e=0;e<u;++e)(o=i.charCodeAt(e))<128?a[c++]=o:o<2048?(a[c++]=192|o>>>6,a[c++]=128|63&o):o<55296||o>=57344?(a[c++]=224|o>>>12,a[c++]=128|o>>>6&63,a[c++]=128|63&o):(o=65536+((1023&o)<<10|1023&i.charCodeAt(++e)),a[c++]=240|o>>>18,a[c++]=128|o>>>12&63,a[c++]=128|o>>>6&63,a[c++]=128|63&o);i=a}else{if("object"!==n)throw new Error(h);if(null===i)throw new Error(h);if(f&&i.constructor===ArrayBuffer)i=new Uint8Array(i);else if(!(Array.isArray(i)||f&&ArrayBuffer.isView(i)))throw new Error(h)}i.length>64&&(i=new t(r,!0).update(i).array());var y=[],p=[];for(e=0;e<64;++e){var l=i[e]||0;y[e]=92^l,p[e]=54^l}t.call(this,r,s),this.update(p),this.oKeyPad=y,this.inner=!0,this.sharedMemory=s}var h="input is invalid type",r="object"==typeof window,s=r?window:{};s.JS_SHA256_NO_WINDOW&&(r=!1);var e=!r&&"object"==typeof self,n=!s.JS_SHA256_NO_NODE_JS&&"object"==typeof process&&process.versions&&process.versions.node;n?s=global:e&&(s=self);var o=!s.JS_SHA256_NO_COMMON_JS&&"object"==typeof module&&module.exports,a="function"==typeof define&&define.amd,f=!s.JS_SHA256_NO_ARRAY_BUFFER&&"undefined"!=typeof ArrayBuffer,u="0123456789abcdef".split(""),c=[-2147483648,8388608,32768,128],y=[24,16,8,0],p=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298],l=["hex","array","digest","arrayBuffer"],d=[];!s.JS_SHA256_NO_NODE_JS&&Array.isArray||(Array.isArray=function(t){return"[object Array]"===Object.prototype.toString.call(t)}),!f||!s.JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW&&ArrayBuffer.isView||(ArrayBuffer.isView=function(t){return"object"==typeof t&&t.buffer&&t.buffer.constructor===ArrayBuffer});var A=function(i,h){return function(r){return new t(h,!0).update(r)[i]()}},w=function(i){var h=A("hex",i);n&&(h=b(h,i)),h.create=function(){return new t(i)},h.update=function(t){return h.create().update(t)};for(var r=0;r<l.length;++r){var s=l[r];h[s]=A(s,i)}return h},b=function(t,i){var r,e=require("crypto"),n=require("buffer").Buffer,o=i?"sha224":"sha256";r=n.from&&!s.JS_SHA256_NO_BUFFER_FROM?n.from:function(t){return new n(t)};return function(i){if("string"==typeof i)return e.createHash(o).update(i,"utf8").digest("hex");if(null===i||void 0===i)throw new Error(h);return i.constructor===ArrayBuffer&&(i=new Uint8Array(i)),Array.isArray(i)||ArrayBuffer.isView(i)||i.constructor===n?e.createHash(o).update(r(i)).digest("hex"):t(i)}},_=function(t,h){return function(r,s){return new i(r,h,!0).update(s)[t]()}},v=function(t){var h=_("hex",t);h.create=function(h){return new i(h,t)},h.update=function(t,i){return h.create(t).update(i)};for(var r=0;r<l.length;++r){var s=l[r];h[s]=_(s,t)}return h};t.prototype.update=function(t){if(!this.finalized){var i,r=typeof t;if("string"!==r){if("object"!==r)throw new Error(h);if(null===t)throw new Error(h);if(f&&t.constructor===ArrayBuffer)t=new Uint8Array(t);else if(!(Array.isArray(t)||f&&ArrayBuffer.isView(t)))throw new Error(h);i=!0}for(var s,e,n=0,o=t.length,a=this.blocks;n<o;){if(this.hashed&&(this.hashed=!1,a[0]=this.block,this.block=a[16]=a[1]=a[2]=a[3]=a[4]=a[5]=a[6]=a[7]=a[8]=a[9]=a[10]=a[11]=a[12]=a[13]=a[14]=a[15]=0),i)for(e=this.start;n<o&&e<64;++n)a[e>>>2]|=t[n]<<y[3&e++];else for(e=this.start;n<o&&e<64;++n)(s=t.charCodeAt(n))<128?a[e>>>2]|=s<<y[3&e++]:s<2048?(a[e>>>2]|=(192|s>>>6)<<y[3&e++],a[e>>>2]|=(128|63&s)<<y[3&e++]):s<55296||s>=57344?(a[e>>>2]|=(224|s>>>12)<<y[3&e++],a[e>>>2]|=(128|s>>>6&63)<<y[3&e++],a[e>>>2]|=(128|63&s)<<y[3&e++]):(s=65536+((1023&s)<<10|1023&t.charCodeAt(++n)),a[e>>>2]|=(240|s>>>18)<<y[3&e++],a[e>>>2]|=(128|s>>>12&63)<<y[3&e++],a[e>>>2]|=(128|s>>>6&63)<<y[3&e++],a[e>>>2]|=(128|63&s)<<y[3&e++]);this.lastByteIndex=e,this.bytes+=e-this.start,e>=64?(this.block=a[16],this.start=e-64,this.hash(),this.hashed=!0):this.start=e}return this.bytes>4294967295&&(this.hBytes+=this.bytes/4294967296<<0,this.bytes=this.bytes%4294967296),this}},t.prototype.finalize=function(){if(!this.finalized){this.finalized=!0;var t=this.blocks,i=this.lastByteIndex;t[16]=this.block,t[i>>>2]|=c[3&i],this.block=t[16],i>=56&&(this.hashed||this.hash(),t[0]=this.block,t[16]=t[1]=t[2]=t[3]=t[4]=t[5]=t[6]=t[7]=t[8]=t[9]=t[10]=t[11]=t[12]=t[13]=t[14]=t[15]=0),t[14]=this.hBytes<<3|this.bytes>>>29,t[15]=this.bytes<<3,this.hash()}},t.prototype.hash=function(){var t,i,h,r,s,e,n,o,a,f=this.h0,u=this.h1,c=this.h2,y=this.h3,l=this.h4,d=this.h5,A=this.h6,w=this.h7,b=this.blocks;for(t=16;t<64;++t)i=((s=b[t-15])>>>7|s<<25)^(s>>>18|s<<14)^s>>>3,h=((s=b[t-2])>>>17|s<<15)^(s>>>19|s<<13)^s>>>10,b[t]=b[t-16]+i+b[t-7]+h<<0;for(a=u&c,t=0;t<64;t+=4)this.first?(this.is224?(e=300032,w=(s=b[0]-1413257819)-150054599<<0,y=s+24177077<<0):(e=704751109,w=(s=b[0]-210244248)-1521486534<<0,y=s+143694565<<0),this.first=!1):(i=(f>>>2|f<<30)^(f>>>13|f<<19)^(f>>>22|f<<10),r=(e=f&u)^f&c^a,w=y+(s=w+(h=(l>>>6|l<<26)^(l>>>11|l<<21)^(l>>>25|l<<7))+(l&d^~l&A)+p[t]+b[t])<<0,y=s+(i+r)<<0),i=(y>>>2|y<<30)^(y>>>13|y<<19)^(y>>>22|y<<10),r=(n=y&f)^y&u^e,A=c+(s=A+(h=(w>>>6|w<<26)^(w>>>11|w<<21)^(w>>>25|w<<7))+(w&l^~w&d)+p[t+1]+b[t+1])<<0,i=((c=s+(i+r)<<0)>>>2|c<<30)^(c>>>13|c<<19)^(c>>>22|c<<10),r=(o=c&y)^c&f^n,d=u+(s=d+(h=(A>>>6|A<<26)^(A>>>11|A<<21)^(A>>>25|A<<7))+(A&w^~A&l)+p[t+2]+b[t+2])<<0,i=((u=s+(i+r)<<0)>>>2|u<<30)^(u>>>13|u<<19)^(u>>>22|u<<10),r=(a=u&c)^u&y^o,l=f+(s=l+(h=(d>>>6|d<<26)^(d>>>11|d<<21)^(d>>>25|d<<7))+(d&A^~d&w)+p[t+3]+b[t+3])<<0,f=s+(i+r)<<0,this.chromeBugWorkAround=!0;this.h0=this.h0+f<<0,this.h1=this.h1+u<<0,this.h2=this.h2+c<<0,this.h3=this.h3+y<<0,this.h4=this.h4+l<<0,this.h5=this.h5+d<<0,this.h6=this.h6+A<<0,this.h7=this.h7+w<<0},t.prototype.hex=function(){this.finalize();var t=this.h0,i=this.h1,h=this.h2,r=this.h3,s=this.h4,e=this.h5,n=this.h6,o=this.h7,a=u[t>>>28&15]+u[t>>>24&15]+u[t>>>20&15]+u[t>>>16&15]+u[t>>>12&15]+u[t>>>8&15]+u[t>>>4&15]+u[15&t]+u[i>>>28&15]+u[i>>>24&15]+u[i>>>20&15]+u[i>>>16&15]+u[i>>>12&15]+u[i>>>8&15]+u[i>>>4&15]+u[15&i]+u[h>>>28&15]+u[h>>>24&15]+u[h>>>20&15]+u[h>>>16&15]+u[h>>>12&15]+u[h>>>8&15]+u[h>>>4&15]+u[15&h]+u[r>>>28&15]+u[r>>>24&15]+u[r>>>20&15]+u[r>>>16&15]+u[r>>>12&15]+u[r>>>8&15]+u[r>>>4&15]+u[15&r]+u[s>>>28&15]+u[s>>>24&15]+u[s>>>20&15]+u[s>>>16&15]+u[s>>>12&15]+u[s>>>8&15]+u[s>>>4&15]+u[15&s]+u[e>>>28&15]+u[e>>>24&15]+u[e>>>20&15]+u[e>>>16&15]+u[e>>>12&15]+u[e>>>8&15]+u[e>>>4&15]+u[15&e]+u[n>>>28&15]+u[n>>>24&15]+u[n>>>20&15]+u[n>>>16&15]+u[n>>>12&15]+u[n>>>8&15]+u[n>>>4&15]+u[15&n];return this.is224||(a+=u[o>>>28&15]+u[o>>>24&15]+u[o>>>20&15]+u[o>>>16&15]+u[o>>>12&15]+u[o>>>8&15]+u[o>>>4&15]+u[15&o]),a},t.prototype.toString=t.prototype.hex,t.prototype.digest=function(){this.finalize();var t=this.h0,i=this.h1,h=this.h2,r=this.h3,s=this.h4,e=this.h5,n=this.h6,o=this.h7,a=[t>>>24&255,t>>>16&255,t>>>8&255,255&t,i>>>24&255,i>>>16&255,i>>>8&255,255&i,h>>>24&255,h>>>16&255,h>>>8&255,255&h,r>>>24&255,r>>>16&255,r>>>8&255,255&r,s>>>24&255,s>>>16&255,s>>>8&255,255&s,e>>>24&255,e>>>16&255,e>>>8&255,255&e,n>>>24&255,n>>>16&255,n>>>8&255,255&n];return this.is224||a.push(o>>>24&255,o>>>16&255,o>>>8&255,255&o),a},t.prototype.array=t.prototype.digest,t.prototype.arrayBuffer=function(){this.finalize();var t=new ArrayBuffer(this.is224?28:32),i=new DataView(t);return i.setUint32(0,this.h0),i.setUint32(4,this.h1),i.setUint32(8,this.h2),i.setUint32(12,this.h3),i.setUint32(16,this.h4),i.setUint32(20,this.h5),i.setUint32(24,this.h6),this.is224||i.setUint32(28,this.h7),t},(i.prototype=new t).finalize=function(){if(t.prototype.finalize.call(this),this.inner){this.inner=!1;var i=this.array();t.call(this,this.is224,this.sharedMemory),this.update(this.oKeyPad),this.update(i),t.prototype.finalize.call(this)}};var B=w();B.sha256=B,B.sha224=w(!0),B.sha256.hmac=v(),B.sha224.hmac=v(!0),o?module.exports=B:(s.sha256=B.sha256,s.sha224=B.sha224,a&&define(function(){return B}))}();
</script>

JSINIT;
}
?>
