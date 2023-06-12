;(function (root, factory) {
  // CommonJS
  module.exports = exports = factory(require("crypto-js/core"), require("crypto-js/cipher-core"));
}(this, function (C) {

  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2016 artjomb
   */
  // Shortcuts
  var C_lib = C.lib;
  var WordArray = C_lib.WordArray;
  var BlockCipher = C_lib.BlockCipher;
  var Hasher = C_lib.Hasher;
  var C_algo = C.algo;

  var Sbox= [0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2];
  var RC = [
  	[0xc7b11940, 0x2be75b5f, 0xe34230e1, 0xc6de7511, 0x503b802a, 0x96a7f546, 0xfd02a80d, 0x8cb27863],
  	[0x6990c02e, 0x24cf9ab9, 0x4c057e4e, 0x08726162, 0xdccb97ca, 0x280e1ccb, 0x6db96161, 0x5a126f97],
  	[0xff223911, 0xf7f604c2, 0x72d7ec72, 0xdb58b760, 0x669de33d, 0xee6be020, 0x2550c439, 0xd270f05e],
  	[0xf5a6c282, 0x0cac1ab3, 0xb263f3f6, 0x8b1d3c53, 0x118bb9d5, 0x2521bd52, 0x0eb7a1e5, 0xa3cb9e5b],
  	[0x1612115e, 0x8201b031, 0x1ea4d23d, 0x2bb3f906, 0x832a6019, 0x1b4181d9, 0xf3f2a22b, 0x9671f3ba],
  	[0xd299ae33, 0xda1d4ed5, 0xed9c5c77, 0x047b758f, 0xe01bb24d, 0x4801a33b, 0x8050013f, 0xbb396b14],
  	[0x1d18fe11, 0xcd6aa678, 0xcfe05345, 0x1418e7db, 0xb8b38222, 0x0290ebd4, 0x2291a6ff, 0x6c4c1743],
  	[0x4afc5e12, 0x77a7355e, 0xc0b5a223, 0x1a9e2ccc, 0x02f555d4, 0x73983656, 0x7bcdef91, 0xd914cfe2],
  	[0xece8b0d3, 0x361a8b56, 0x9fe8cecb, 0x31b9ecd7, 0xe730d51a, 0xb9f94b62, 0x0357d728, 0xfdbeda72],
  	[0x1e5d2b7b, 0xfca2f0cc, 0xe303b2bf, 0x33be3dc4, 0xce608823, 0x98bb64f6, 0x0b7adb09, 0x2bface29],
  	[0x89a2a6a2, 0xbaf87b87, 0x05ead754, 0x47d16334, 0x479ad1f8, 0x7a467e12, 0x45e036f2, 0x119df0eb],
  	[0x96b97098, 0x1eb889eb, 0x988a96bf, 0x01fc1dd1, 0x3a0c1195, 0x19ffe345, 0x90a0fe36, 0xc225749e],
  	[0x10f20d64, 0xbe3da278, 0x3114fe4d, 0xfaef826d, 0xb18e6e25, 0xcf42ff6f, 0x22a604a3, 0x496878d6],
  	[0x104d1cdd, 0xe66f4731, 0x2729c321, 0xe0ca3b99, 0xd39b7546, 0x72e3910d, 0x6a4ddc20, 0x4a7989f6],
  	[0x3b346ce0, 0x5703de7e, 0xb2719130, 0xaf1b4266, 0x60aac324, 0x3e43b223, 0x4b95c10d, 0x28d13528],
  	[0x786d7809, 0x21f9490b, 0x94476162, 0x609fd9e1, 0x00c2fdb3, 0x47fe2208, 0x086b1d8f, 0xc2459661],
  	[0x888460b5, 0x299cee14, 0xe2095e06, 0x76c4ee73, 0xaef17819, 0x767cd8ee, 0x92231629, 0x28c83763],
  	[0xe80f465c, 0x9f7cfc78, 0xa49539b7, 0x37812cbc, 0xdcd37347, 0xcf4d4025, 0xac70a243, 0x56ef05d3],
  	[0xce366bd8, 0x78a92187, 0x86f4fdde, 0xf33e2ad5, 0x1012edbd, 0xe19085f0, 0xebcee846, 0x38fa7126],
  	[0x76a45e9f, 0xeb2c4123, 0x37044827, 0x8054b494, 0xb62d481b, 0x5c8403a1, 0xcab5529b, 0xea62b745],
  	[0xadf6d3e9, 0x3166a6f8, 0x92b0a9d5, 0x9d55a1a5, 0x1ca11b9c, 0xb530d7f5, 0xd50946dd, 0x9ceeda2c],
  	[0x3246b10c, 0x987b174f, 0xd9f59844, 0x4a5c42e9, 0xea390cf5, 0xc4c5a5fd, 0xba7e0a08, 0xf59d2f10],
  	[0x9f3903e5, 0x338b6415, 0xd92b4707, 0x462d4ef8, 0x2844f789, 0x7dcf8f70, 0x2e131c06, 0x2682a99a],
  	[0x70ff29c4, 0xc11f1800, 0x8dd533ac, 0xd7248c9b, 0x0a642eba, 0xf42b4fb2, 0x0898288b, 0x394e5f33],
  	[0xcb8befdf, 0xdf5b238b, 0x1c730c0b, 0xf30855bb, 0xc7a0bfa5, 0xae3516ab, 0x7edd326f, 0x5611ae48],
  	[0xdfeb2867, 0x2f6bcfc1, 0xafb3d11a, 0x97bbe65f, 0xc0ffb97d, 0x526913fc, 0xa74d7e99, 0x5ba9a3a6],
  	[0x9f7f4896, 0x467352c8, 0x24c941af, 0x49866c11, 0x246f4529, 0xd55c0b11, 0x10b90475, 0x75249533],
  	[0x79990702, 0x621c5311, 0x45378996, 0x444dc267, 0x629c221a, 0x9d6fc3d7, 0x5be71d70, 0x4ae1bac2],
  	[0x5f6731bf, 0x692923f1, 0xb6d1dce7, 0x4905c7ca, 0x504acba3, 0xd0b95bc7, 0x9d778702, 0x5783e5cf],
  	[0xec1d0d8d, 0xdd6b5d8d, 0xcf1c5a75, 0x9fae7dc0, 0xc206489b, 0xc8f14d8d, 0x9e4a6bcb, 0x2287c7c3],
  	[0xfc2d8fd0, 0x4b8f582f, 0xadd6205c, 0xa979b648, 0xa2c6fc9b, 0x00ca8b38, 0x9cd94a3e, 0xf90ad435],
  	[0x40e308b3, 0x8501c427, 0x3130a587, 0x906a0ccc, 0x5461f947, 0xf201759b, 0x50b61dd3, 0x2adedb9a]
  ];

  function f(msgWord, cv){
  	var i, j, k, word, carry, prevCarry;

  	cv[0] ^= msgWord;
  	for(i = 0; i < 32; i++) {
  		// Apply Sbox 64 times
  		for(j = 0; j < 8; j++) {
  			word = 0;
  			for(k = 0; k < 8; k++) {
  				word |= Sbox[(cv[j] >>> (28 - 4 * k)) & 0xf] << (28 - 4 * k);
  			}
  			cv[j] = word;
  		}

  		// XOR 3 16-bit words into the first one 4 times
  		for(j = 0; j < 4; j++) {
  			word = cv[j*2+1] & 0xffff;
  			cv[2*j] = (((cv[j*2] >>> 16) ^ word) << 16) | ((cv[j*2] ^ word) & 0xffff);
  			cv[2*j+1] = (cv[2*j+1] ^ (word << 16)) | 0;
  		}

  		// rotate left by 8 bit
  		prevCarry = cv[0] >>> 24;
  		for(j = 7; j >= 0; j--) {
  			carry = cv[j] >>> 24;
  			cv[j] <<= 8;
  			cv[j] |= prevCarry;
  			prevCarry = carry;
  		}

  		// ADD round constant RC[i]
  		for(j = 0; j < 8; j++) {
  			cv[j] = (((cv[j] >>> 16) + (RC[i][j] >>> 16)) << 16) | ((cv[j] + RC[i][j]) & 0xffff);
  		}
  	}
  }

  var Neeva = C_algo.Neeva = Hasher.extend({
  	_doReset: function () {
  		this._cv = [0, 0, 0, 0, 0, 0, 0, 0];
  	},

  	_doProcessBlock: function (M, offset) {
  		// absorbing
  		f(M[offset], this._cv);
  	},

  	_doFinalize: function () {
  		// Shortcuts
  		var self = this;
  		var data = self._data;
  		var dataWords = data.words;

  		var nBitsTotal = self._nDataBytes * 8;
  		var nBitsLeft = data.sigBytes * 8;

  		var hash = [];
  		var cv = self._cv;
  		var i;

  		// Add padding
  		dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32) | 1; // 1 0^* 1 to fill the next 32-bit word
  		data.sigBytes = dataWords.length * 4;

  		// Hash final blocks
  		self._process();

  		// squeezing
  		hash[0] = cv[0];
  		for(i = 1; i < 7; i++) {
  			f(0, cv);
  			hash[i] = cv[0];
  		}

  		// Return final computed hash
  		return new WordArray.init(hash);
  	},

  	clone: function () {
  		var clone = Hasher.clone.call(this);
  		clone._hash = this._hash.clone();

  		return clone;
  	},

  	blockSize: 32/32,
  	outputSize: 224/32
  });

  C.Neeva = Hasher._createHelper(Neeva);


}));