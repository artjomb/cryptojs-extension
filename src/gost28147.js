/* 
 * The MIT License (MIT)
 * 
 * Copyright (c) 2015 artjomb
 */
(function(C){
	// Shortcuts
	var C_lib = C.lib;
	var BlockCipher = C_lib.BlockCipher;
	var C_algo = C.algo;

	/* Port from https://github.com/sftp/gost28147 */

	/*
	 * RFC 4357 section 11.2
	 */
	var sbox = [
		[  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 ],
		[ 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 ],
		[  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 ],
		[  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 ],
		[  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 ],
		[  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 ],
		[ 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 ],
		[  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 ]
	];
	
	var sbox_x = [];

	(function init_sbox_x(sbox, sbox_x)
	{
		var i, j, k;

		for (i = 0, j = 0; i < 4; i++, j += 2) {
			sbox_x.push([]);
			for (k = 0; k < 256; k++) {
				sbox_x[i][k] = (sbox[j][k & 0x0f] | sbox[j+1][k>>4] << 4) << (j*4);
				sbox_x[i][k] = sbox_x[i][k] << 11 | sbox_x[i][k] >> (32-11);
			}
		}
	}(sbox, sbox_x));

	function f(word)
	{
		return sbox_x[3][word >> 24] ^
			sbox_x[2][(word & 0x00ff0000) >> 16] ^
			sbox_x[1][(word & 0x0000ff00) >>  8] ^
			sbox_x[0][(word & 0x000000ff)];
	}

	function encrypt_block(l, r, key)
	{
		var i;

		for (i = 0; i < 23; i += 2) {
			l ^= f(r + key[i % 8]);
			r ^= f(l + key[(i+1) % 8]);
		}

		for (i = 24; i < 31; i += 2) {
			l ^= f(r + key[31-i]);
			r ^= f(l + key[31-(i+1)]);
		}

		return [r, l];
	}

	function decrypt_block(l, r, key)
	{
		var i;

		for (i = 0; i < 7; i += 2) {
			l ^= f(r + key[i]);
			r ^= f(l + key[i+1]);
		}

		for (i = 8; i < 31; i += 2) {
			l ^= f(r + key[(31-i) % 8]);
			r ^= f(l + key[(31-(i+1)) % 8]);
		}

		return [r, l];
	}

	function calc_mac(l, r, key)
	{
		var i;
	 
		for (i = 0; i < 15; i += 2) {
			l ^= f(r + key[i % 8]);
			r ^= f(l + key[(i+1) % 8]);
		}

		return [l, r];
	}
	
	function check_key(keyWordArray){
		var words = keyWordArray.words,
			i;
		if (!words) {
			words = [];
		}
		for(i = words.length; i < 8; i++) {
			words.push(0);
		}
		return words;
	}
	
	/**
	 * GOST 28147-89 (ГОСТ 28147-89) block cipher algorithm.
	 */
	var Gost28147 = C_algo.Gost28147 = BlockCipher.extend({
		_doReset: function () {},

		encryptBlock: function (M, offset) {
			var block = encrypt_block(M[offset], M[offset+1], check_key(this._key))
			M[offset] = block[0];
			M[offset+1] = block[1];
		},

		decryptBlock: function (M, offset) {
			var block = decrypt_block(M[offset], M[offset+1], check_key(this._key))
			M[offset] = block[0];
			M[offset+1] = block[1];
		},

		blockSize: 64/32,
		keySize: 256/32
	});
	
	C.Gost28147 = BlockCipher._createHelper(Gost28147);
})(CryptoJS);