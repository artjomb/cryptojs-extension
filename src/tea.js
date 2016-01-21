/* 
 * The MIT License (MIT)
 * 
 * Copyright (c) 2016 artjomb
 */
(function (C) {
	// Shortcuts
	var C_lib = C.lib;
	var BlockCipher = C_lib.BlockCipher;
	var C_algo = C.algo;
	var WordArray = C_lib.WordArray;

	var delta = 0x9e3779b9

	/**
	 * TEA block cipher algorithm.
	 */
	var TEA = C_algo.TEA = BlockCipher.extend({
		_doReset: function () {
			var k = this._key;
			var words = k.words;
			k.sigBytes = 16;
			words.length = 4;
			words[0] |= 0;
			words[1] |= 0;
			words[2] |= 0;
			words[3] |= 0;
		},

		encryptBlock: function (M, offset) {
			var k = this._key.words;
			var v0 = M[offset], v1 = M[offset+1], sum = 0, i;
			var k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
			for (i = 0; i < this.nRounds; i++) {
				sum = (sum + delta) | 0;
				v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >>> 5) + k1))) | 0;
				v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >>> 5) + k3))) | 0;
			}
			M[offset] = v0; 
			M[offset + 1] = v1;
		},

		decryptBlock: function (M, offset) {
			var k = this._key.words;
			var v0 = M[offset], v1 = M[offset+1], sum = 0xC6EF3720, i;
			var k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
			for (i = 0; i < this.nRounds; i++) {
				v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >>> 5) + k3))) | 0;
				v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >>> 5) + k1))) | 0;
				sum = (sum - delta) | 0;
			}
			M[offset] = v0; 
			M[offset + 1] = v1;
		},

		nRounds: 32,
		blockSize: 64/32
	});

	/**
	 * Shortcut functions to the cipher's object interface.
	 *
	 * @example
	 *
	 *     var ciphertext = CryptoJS.TEA.encrypt(message, key, cfg);
	 *     var plaintext  = CryptoJS.TEA.decrypt(ciphertext, key, cfg);
	 */
	C.TEA = BlockCipher._createHelper(TEA);
}(CryptoJS));