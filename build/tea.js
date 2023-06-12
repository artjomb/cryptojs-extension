;(function (root, factory, undef) {
  if (typeof define === "function" && define.amd) {
    // AMD
    define(["crypto-js/core", "crypto-js/cipher-core"], factory);
  }
  else {
    // Global (browser)
    factory(root.CryptoJS);
  }
}(this, function (C) {

  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2016 artjomb
   */
  // Shortcuts
  var C_lib = C.lib;
  var BlockCipher = C_lib.BlockCipher;
  var C_algo = C.algo;
  var WordArray = C_lib.WordArray;

  var delta = 0x9e3779b9;

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
  		var rounds = this.nRounds;
  		var v0 = M[offset], v1 = M[offset+1], sum = (rounds * delta) | 0, i;
  		var k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
  		for (i = 0; i < rounds; i++) {
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
   * XTEA block cipher algorithm.
   */
  var XTEA = C_algo.XTEA = TEA.extend({
  	encryptBlock: function (M, offset) {
  		var k = this._key.words;
  		var v0 = M[offset], v1 = M[offset+1], sum = 0, i;
  		var k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
  		for (i = 0; i < this.nRounds; i++) {
  			v0 = (v0 + ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + k[sum & 3]))) | 0;
  			sum = (sum + delta) | 0;
  			v1 = (v1 + ((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + k[(sum >>> 11) & 3]))) | 0;
  		}
  		M[offset] = v0;
  		M[offset + 1] = v1;
  	},

  	decryptBlock: function (M, offset) {
  		var k = this._key.words;
  		var rounds = this.nRounds;
  		var v0 = M[offset], v1 = M[offset+1], sum = (rounds * delta) | 0, i;
  		var k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
  		for (i = 0; i < this.nRounds; i++) {
  			v1 = (v1 - ((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + k[(sum >>> 11) & 3]))) | 0;
  			sum = (sum - delta) | 0;
  			v0 = (v0 - ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + k[sum & 3]))) | 0;
  		}
  		M[offset] = v0;
  		M[offset + 1] = v1;
  	}
  });

  /**
   * XXTEA block cipher algorithm with a 64 bit block size.
   */
  var XXTEA = C_algo.XXTEA = TEA.extend({
  	encryptBlock: function (M, offset) {
  		var self = this,
  			k = self._key.words,
  			n = self.blockSize,
  			rounds = 6 + ((52/n) | 0),
  			z = M[offset + n - 1],
  			e,
  			sum = 0,
  			p;

  		do {
  			sum = (sum + delta) | 0;
  			e = (sum >>> 2) & 3;
  			for (p = 0; p < n-1; p++) {
  				y = M[offset + p + 1];
  				M[offset + p] = (M[offset + p] + (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)))) | 0;
  				z = M[offset + p];
  			}
  			y = M[offset];
  			M[offset + n - 1] = (M[offset + n - 1] + (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)))) | 0;
  			z = M[offset + n - 1];
  		} while (--rounds);
  	},

  	decryptBlock: function (M, offset) {
  		var self = this,
  			k = self._key.words,
  			n = self.blockSize,
  			rounds = 6 + ((52/n) | 0),
  			z = M[offset + n - 1],
  			e,
  			sum = (rounds*delta) | 0,
  			p;

  		y = M[offset];
  		do {
  			e = (sum >>> 2) & 3;
  			for (p = n-1; p > 0; p--) {
  				z = M[offset + p - 1];
  				M[offset + p] = (M[offset + p] - (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)))) | 0;
  				y = M[offset + p];
  			}
  			z = M[offset + n - 1];
  			M[offset] = (M[offset] - (((z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)))) | 0;
  			y = M[offset];
  			sum = (sum - delta) | 0;
  		} while (--rounds);
  	}
  });

  /**
   * XXTEA block cipher algorithm with a 96 bit block size.
   */
  var XXTEA96 = C_algo.XXTEA96 = XXTEA.extend({
  	blockSize: 96/32
  });

  /**
   * XXTEA block cipher algorithm with a 128 bit block size.
   */
  var XXTEA128 = C_algo.XXTEA128 = XXTEA.extend({
  	blockSize: 128/32
  });

  /**
   * XXTEA block cipher algorithm with a 256 bit block size.
   */
  var XXTEA256 = C_algo.XXTEA256 = XXTEA.extend({
  	blockSize: 256/32
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

  /**
   * Shortcut functions to the cipher's object interface.
   *
   * @example
   *
   *     var ciphertext = CryptoJS.XTEA.encrypt(message, key, cfg);
   *     var plaintext  = CryptoJS.XTEA.decrypt(ciphertext, key, cfg);
   */
  C.XTEA = BlockCipher._createHelper(XTEA);

  /**
   * Shortcut functions to the cipher's object interface.
   *
   * @example
   *
   *     var ciphertext = CryptoJS.XXTEA.encrypt(message, key, cfg);
   *     var plaintext  = CryptoJS.XXTEA.decrypt(ciphertext, key, cfg);
   */
  C.XXTEA = C.XXTEA64 = BlockCipher._createHelper(XXTEA);
  C.XXTEA96 = BlockCipher._createHelper(XXTEA96);
  C.XXTEA128 = BlockCipher._createHelper(XXTEA128);
  C.XXTEA256 = BlockCipher._createHelper(XXTEA256);


}));