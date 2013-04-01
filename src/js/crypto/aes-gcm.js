'use strict';

/**
 * A Wrapper for SJCL's authenticated AES-GCM encryption
 */
app.crypto.AesGCM = function() {
	
	var adata = [];		// authenticated data (empty by default)
	var tlen = 128;		// The tag length in bits
	
	/**
	 * Encrypt a String using AES-GCM using the provided keysize (e.g. 128, 256)
	 * @param plaintext [String] The input string in UTF8
	 * @param key [String] The base64 encoded key
	 * @param iv [String] The base64 encoded IV
	 * @return [String] The base64 encoded ciphertext
	 */
	this.encrypt = function(plaintext, key, iv) {
		// convert parameters to WordArrays
		var keyWords = sjcl.codec.base64.toBits(key);
		var ivWords = sjcl.codec.base64.toBits(iv);
		var plaintextWords = sjcl.codec.utf8String.toBits(plaintext);
		
		var blockCipher = new sjcl.cipher.aes(keyWords);
		var ciphertext = sjcl.mode.gcm.encrypt(blockCipher, plaintextWords, ivWords, adata, tlen);
		var ctBase64 = sjcl.codec.base64.fromBits(ciphertext);
		
		return ctBase64;
	};
	
	/**
	 * Decrypt a String using AES-GCM using the provided keysize (e.g. 128, 256)
	 * @param ciphertext [String] The base64 encoded ciphertext
	 * @param key [String] The base64 encoded key
	 * @param iv [String] The base64 encoded IV
	 * @return [String] The decrypted plaintext in UTF8
	 */
	this.decrypt = function(ciphertext, key, iv) {
		// convert parameters to WordArrays
		var keyWords = sjcl.codec.base64.toBits(key);
		var ivWords = sjcl.codec.base64.toBits(iv);
		var ciphertextWords = sjcl.codec.base64.toBits(ciphertext);
		
		var blockCipher = new sjcl.cipher.aes(keyWords);
		var decrypted = sjcl.mode.gcm.decrypt(blockCipher, ciphertextWords, ivWords, adata, tlen);
		var pt = sjcl.codec.utf8String.fromBits(decrypted);
		
		return pt;
	};

};