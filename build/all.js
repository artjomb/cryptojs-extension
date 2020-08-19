;(function (root, factory) {
  if (typeof define === "function" && define.amd) {
    // AMD
    define(["crypto-js/core"], factory);
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

  // port of https://sites.google.com/site/spongenthash/

  var Sbox8 = [
  	// 0xee, 0xed, 0xeb, 0xe0, 0xe2, 0xe1, 0xe4, 0xef, 0xe7, 0xea, 0xe8, 0xe5, 0xe9, 0xec, 0xe3, 0xe6,
  	// 0xde, 0xdd, 0xdb, 0xd0, 0xd2, 0xd1, 0xd4, 0xdf, 0xd7, 0xda, 0xd8, 0xd5, 0xd9, 0xdc, 0xd3, 0xd6,
  	// 0xbe, 0xbd, 0xbb, 0xb0, 0xb2, 0xb1, 0xb4, 0xbf, 0xb7, 0xba, 0xb8, 0xb5, 0xb9, 0xbc, 0xb3, 0xb6,
  	// 0x0e, 0x0d, 0x0b, 0x00, 0x02, 0x01, 0x04, 0x0f, 0x07, 0x0a, 0x08, 0x05, 0x09, 0x0c, 0x03, 0x06,
  	// 0x2e, 0x2d, 0x2b, 0x20, 0x22, 0x21, 0x24, 0x2f, 0x27, 0x2a, 0x28, 0x25, 0x29, 0x2c, 0x23, 0x26,
  	// 0x1e, 0x1d, 0x1b, 0x10, 0x12, 0x11, 0x14, 0x1f, 0x17, 0x1a, 0x18, 0x15, 0x19, 0x1c, 0x13, 0x16,
  	// 0x4e, 0x4d, 0x4b, 0x40, 0x42, 0x41, 0x44, 0x4f, 0x47, 0x4a, 0x48, 0x45, 0x49, 0x4c, 0x43, 0x46,
  	// 0xfe, 0xfd, 0xfb, 0xf0, 0xf2, 0xf1, 0xf4, 0xff, 0xf7, 0xfa, 0xf8, 0xf5, 0xf9, 0xfc, 0xf3, 0xf6,
  	// 0x7e, 0x7d, 0x7b, 0x70, 0x72, 0x71, 0x74, 0x7f, 0x77, 0x7a, 0x78, 0x75, 0x79, 0x7c, 0x73, 0x76,
  	// 0xae, 0xad, 0xab, 0xa0, 0xa2, 0xa1, 0xa4, 0xaf, 0xa7, 0xaa, 0xa8, 0xa5, 0xa9, 0xac, 0xa3, 0xa6,
  	// 0x8e, 0x8d, 0x8b, 0x80, 0x82, 0x81, 0x84, 0x8f, 0x87, 0x8a, 0x88, 0x85, 0x89, 0x8c, 0x83, 0x86,
  	// 0x5e, 0x5d, 0x5b, 0x50, 0x52, 0x51, 0x54, 0x5f, 0x57, 0x5a, 0x58, 0x55, 0x59, 0x5c, 0x53, 0x56,
  	// 0x9e, 0x9d, 0x9b, 0x90, 0x92, 0x91, 0x94, 0x9f, 0x97, 0x9a, 0x98, 0x95, 0x99, 0x9c, 0x93, 0x96,
  	// 0xce, 0xcd, 0xcb, 0xc0, 0xc2, 0xc1, 0xc4, 0xcf, 0xc7, 0xca, 0xc8, 0xc5, 0xc9, 0xcc, 0xc3, 0xc6,
  	// 0x3e, 0x3d, 0x3b, 0x30, 0x32, 0x31, 0x34, 0x3f, 0x37, 0x3a, 0x38, 0x35, 0x39, 0x3c, 0x33, 0x36,
  	// 0x6e, 0x6d, 0x6b, 0x60, 0x62, 0x61, 0x64, 0x6f, 0x67, 0x6a, 0x68, 0x65, 0x69, 0x6c, 0x63, 0x66
  ];

  (function(){
  	var Sbox = [0xe, 0xd, 0xb, 0x0, 0x2, 0x1, 0x4, 0xf, 0x7, 0xa, 0x8, 0x5, 0x9, 0xc, 0x3, 0x6],
  		i,
  		j;
  	for(i = 0; i < 16; i++){
  		for(j = 0; j < 16; j++){
  			Sbox8[i*16 + j] = (Sbox[i]<<4) | Sbox[j];
  		}
  	}
  })();

  function lCounter(version, lfsr) {
  	switch(version) {
  		case     88808:
  			lfsr = (lfsr << 1) | (((0x20 & lfsr) >>> 5) ^ ((0x10 & lfsr) >>> 4));
  			lfsr &= 0x3f;
  			break;
  		case   1281288:
  		case  16016016:
  		case  16016080:
  		case  22422416:
  			lfsr = (lfsr << 1) | (((0x40 & lfsr) >>> 6) ^ ((0x20 & lfsr) >>> 5));
  			lfsr &= 0x7f;
  			break;
  		case   8817688:
  		case 128256128:
  		case 160320160:
  		case 224224112:
  		case  25625616:
  		case 256256128:
  			lfsr = (lfsr << 1) | (((0x80 & lfsr) >>> 7) ^ ((0x08 & lfsr) >>> 3) ^ ((0x04 & lfsr) >>> 2) ^ ((0x02 & lfsr) >>> 1));
  			lfsr &= 0xff;
  			break;
  		case 224448224:
  		case 256512256:
  			lfsr = (lfsr << 1) | (((0x100 & lfsr) >>> 8) ^ ((0x08 & lfsr) >>> 3));
  			lfsr &= 0x1ff;
  			break;
  	}
  	return lfsr;
  }

  function retnuoCl(version, lfsr) {
  	switch(version) {
  		case     88808:
  		case   8817688:
  		case   1281288:
  		case 128256128:
  		case  16016016:
  		case  16016080:
  		case 160320160:
  		case  22422416:
  		case 224224112:
  		case  25625616:
  		case 256256128:
  			lfsr = ( ((lfsr & 0x01) << 7) | ((lfsr & 0x02) << 5) | ((lfsr & 0x04) << 3) | ((lfsr & 0x08) << 1) | ((lfsr & 0x10) >>> 1) | ((lfsr & 0x20) >>> 3) | ((lfsr & 0x40) >>> 5) | ((lfsr & 0x80) >>> 7) );
  			lfsr <<= 8;
  			break;
  		case 224448224:
  		case 256512256:
  			lfsr = ( ((lfsr & 0x01) << 8) | ((lfsr & 0x02) << 6) | ((lfsr & 0x04) << 4) | ((lfsr & 0x08) << 2) | ((lfsr & 0x10)) | ((lfsr & 0x20) >>> 2) | ((lfsr & 0x40) >>> 4) | ((lfsr & 0x80) >>> 6) | ((lfsr & 0x100) >>> 8) );
  			lfsr <<= 7;
  			break;
  	}

  	return lfsr;
  }

  function pi(self, i) {
  	var nBits = self.__nBits;
  	if (i != nBits-1)
  		return ((i*nBits/4)|0)%(nBits-1);
  	else
  		return nBits-1;
  }

  function pLayer(self) {
  	var i, j, PermutedBitNo, x, y,
  		tmp = [],
  		nSBox = self.__nSBox,
  		value = self.__val;

  	for(i = 0; i < nSBox; i++) tmp[i] = 0;

  	for(i = 0; i < nSBox; i++){
  		for(j = 0; j < 8; j++){
  			x = (value[i] >>> j) & 1;
  			PermutedBitNo = pi(self, 8*i+j);
  			y = (PermutedBitNo/8)|0;
  			tmp[y] ^= x << (PermutedBitNo - 8*y);
  		}
  	}

  	for(i = 0; i < nSBox; i++) value[i] = tmp[i];
  }

  function permute(self) {
  	var i, j, IV, INV_IV,
  		nRounds = self.__nRounds,
  		nSBox = self.__nSBox,
  		value = self.__val,
  		version = self.__version;

  	switch(self.__version)
  	{
  		case     88808:	IV = 0x05;	break;
  		case   8817688:	IV = 0xC6;	break;
  		case   1281288:	IV = 0x7A;	break;
  		case 128256128:	IV = 0xFB;	break;
  		case  16016016:	IV = 0x45;	break;
  		case  16016080:	IV = 0x01;	break;
  		case 160320160:	IV = 0xA7;	break;
  		case  22422416:	IV = 0x01;	break;
  		case 224224112:	IV = 0x52;	break;
  		case 224448224:	IV = 0x105; break;
  		case  25625616:	IV = 0x9e;	break;
  		case 256256128:	IV = 0xfb;	break;
  		case 256512256:	IV = 0x015;	break;
  	}

  	for(i = 0; i < nRounds; i++){
  		/* Add counter values */
  		value[0] ^= IV & 0xFF;
  		value[1] ^= (IV >> 8) & 0xFF;
  		INV_IV	= retnuoCl(version, IV);
  		value[nSBox-1] ^= (INV_IV >> 8) & 0xFF;
  		value[nSBox-2] ^= INV_IV & 0xFF;
  		IV	= lCounter(version, IV);

  		/* Sbox8 layer */
  		for (j = 0; j < nSBox; j++) {
  			value[j] = Sbox8[value[j]];
  		}

  		/* pLayer */
  		pLayer(self);
  	}
  	self.__val = value;
  }

  function absorb(self, messageBlock){
  	var i;
  	for(i = 0; i < messageBlock.length; i++) {
  		self.__val[i] ^= messageBlock[i];
  	}
  	permute(self);
  }

  function squeeze(self, finish){
  	var i;
  	for(i = 0; i < self.__R_SizeInBytes; i++) {
  		self.__hash.push(self.__val[i]);
  	}
  	if (!finish) {
  		permute(self);
  	}
  }

  function wordToByteArray(word, length) {
  	var ba = [],
  		i,
  		xFF = 0xFF;
  	if (length > 0)
  		ba.push(word >>> 24);
  	if (length > 1)
  		ba.push((word >>> 16) & xFF);
  	if (length > 2)
  		ba.push((word >>> 8) & xFF);
  	if (length > 3)
  		ba.push(word & xFF);

  	return ba;
  }

  function byteArrayToWordArray(ba) {
  	var wa = [],
  		i;
  	for(i = 0; i < ba.length; i++) {
  		wa[(i/4)|0] |= ba[i] << (24 - 8 * i);
  	}

  	return new WordArray.init(wa, ba.length);
  }

  var Spongent88808 = C_algo.Spongent = C_algo.Spongent88808 = Hasher.extend({
  	_doReset: function () {
  		var self = this;
  		self.__R_SizeInBytes = (self.__rate / 8) | 0;
  		self.__nBits = (self.__capacity + self.__rate) | 0;
  		self.__nSBox = (self.__nBits / 8) | 0;
  		self.__val = Array.apply(null, Array(self.__nSBox)).map(function(){return 0;});
  		self.__buf = [];
  		self.__hash = [];
  	},

  	_doProcessBlock: function (M, offset) {
  		var ba = wordToByteArray(M[offset], 4),
  			self = this,
  			buf = self.__buf;
  		buf = self.__buf = buf.concat(ba);
  		while (buf.length >= self.__R_SizeInBytes) {
  			// absorbing
  			absorb(self, buf.splice(0, self.__R_SizeInBytes));
  		}
  	},

  	_doFinalize: function () {
  		this._process();

  		// Shortcuts
  		var self = this;
  		var data = self._data;
  		var dataWords = data.words;

  		var nBitsTotal = self._nDataBytes * 8;
  		var nBitsLeft = data.sigBytes * 8;

  		var i;

  		// Add padding
  		dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32); // 1 0^(r-1) to fill the next 32-bit word
  		var sigBytes = data.sigBytes + 1;
  		var lastMsgBytes = [];
  		var msgBuffer = self.__buf;

  		for(i = 0; i < dataWords.length; i++) {
  			lastMsgBytes = lastMsgBytes.concat(wordToByteArray(dataWords[i], Math.min(sigBytes, 4)));
  			sigBytes -= 4;
  		}
  		msgBuffer = self.__buf = msgBuffer.concat(lastMsgBytes);

  		// Finish adding padding
  		while((msgBuffer.length % self.__R_SizeInBytes) !== 0) {
  			msgBuffer.push(0);
  		}

  		while(msgBuffer.length > 0) {
  			absorb(self, msgBuffer.splice(0, self.__R_SizeInBytes));
  		}

  		// squeeze all (skip permute on the last squeeze)
  		while(self.__hash.length * 8 !== self.__hashsize) {
  			squeeze(self, (self.__hash.length * 8 + self.__rate) === self.__hashsize);
  		}

  		// Return final computed hash
  		return byteArrayToWordArray(self.__hash);
  	},

  	clone: function () {
  		var clone = Hasher.clone.call(this);
  		clone._hash = this._hash.clone();

  		return clone;
  	},

  	blockSize: 32/32,
  	outputSize: 88/32,
  	__rate: 8,
  	__capacity: 80,
  	__hashsize: 88,
  	__nRounds: 45,
  	__version: 88808
  });
  C.Spongent88808 = Hasher._createHelper(Spongent88808);

  [
  	// ["rate", "capacity", "hashsize", "nRounds", "version"],
  	[88, 176, 88, 135, 8817688],
  	[88, 176, 88, 135, 8817688],
  	[8, 128, 128, 70, 1281288],
  	[128, 256, 128, 195, 128256128],
  	[16, 160, 160, 90, 16016016],
  	[80, 160, 160, 120, 16016080],
  	[160, 320, 160, 240, 160320160],
  	[16, 224, 224, 120, 22422416],
  	[112, 224, 224, 170, 224224112],
  	[224, 448, 224, 340, 224448224],
  	[16, 256, 256, 140, 25625616],
  	[128, 256, 256, 195, 256256128],
  	[256, 512, 256, 385, 256512256]
  ].forEach(function(c){
  	var name = "Spongent" + c[4],
  		SpongentVersion = C_algo[name] = Spongent88808.extend({
  			outputSize: c[2]/32,
  			__rate: c[0],
  			__capacity: c[1],
  			__hashsize: c[2],
  			__nRounds: c[3],
  			__version: c[4]
  		});
  		C[name] = Hasher._createHelper(SpongentVersion);
  });


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  // Shortcuts
  var Base = C.lib.Base;
  var WordArray = C.lib.WordArray;
  var AES = C.algo.AES;
  var ext = C.ext;
  var OneZeroPadding = C.pad.OneZeroPadding;
  var CMAC = C.algo.CMAC;

  /**
   * updateAAD must be used before update, because the additional data is
   * expected to be authenticated before the plaintext stream starts.
   */
  var S2V = C.algo.S2V = Base.extend({
      init: function(key){
          this._blockSize = 16;
          this._cmacAD = CMAC.create(key);
          this._cmacPT = CMAC.create(key);
          this.reset();
      },
      reset: function(){
          this._buffer = new WordArray.init();
          this._cmacAD.reset();
          this._cmacPT.reset();
          this._d = this._cmacAD.finalize(ext.const_Zero);
          this._empty = true;
          this._ptStarted = false;
      },
      updateAAD: function(msgUpdate){
          if (this._ptStarted) {
              // It's not possible to authenticate any more additional data when the plaintext stream starts
              return this;
          }

          if (!msgUpdate) {
              return this;
          }

          if (typeof msgUpdate === "string") {
              msgUpdate = C.enc.Utf8.parse(msgUpdate);
          }

          this._d = ext.xor(ext.dbl(this._d), this._cmacAD.finalize(msgUpdate));
          this._empty = false;

          // Chainable
          return this;
      },
      update: function(msgUpdate){
          if (!msgUpdate) {
              return this;
          }

          this._ptStarted = true;
          var buffer = this._buffer;
          var bsize = this._blockSize;
          var wsize = bsize / 4;
          var cmac = this._cmacPT;
          if (typeof msgUpdate === "string") {
              msgUpdate = C.enc.Utf8.parse(msgUpdate);
          }

          buffer.concat(msgUpdate);

          while(buffer.sigBytes >= 2 * bsize){
              this._empty = false;
              var s_i = ext.popWords(buffer, wsize);
              cmac.update(s_i);
          }

          // Chainable
          return this;
      },
      finalize: function(msgUpdate){
          this.update(msgUpdate);

          var bsize = this._blockSize;
          var s_n = this._buffer;

          if (this._empty && s_n.sigBytes === 0) {
              return this._cmacAD.finalize(ext.const_One);
          }

          var t;
          if (s_n.sigBytes >= bsize) {
              t = ext.xorendBytes(s_n, this._d);
          } else {
              OneZeroPadding.pad(s_n, bsize);
              t = ext.xor(ext.dbl(this._d), s_n);
          }

          return this._cmacPT.finalize(t);
      }
  });

  var SIV = C.SIV = Base.extend({
      init: function(key){
          var len = key.sigBytes / 2;
          this._s2vKey = ext.shiftBytes(key, len);
          this._ctrKey = key;
      },
      encrypt: function(adArray, plaintext){
          if (!plaintext && adArray) {
              plaintext = adArray;
              adArray = [];
          }

          var s2v = S2V.create(this._s2vKey);
          Array.prototype.forEach.call(adArray, function(ad){
              s2v.updateAAD(ad);
          });
          var tag = s2v.finalize(plaintext);
          var filteredTag = ext.bitand(tag, ext.const_nonMSB);

          var ciphertext = C.AES.encrypt(plaintext, this._ctrKey, {
              iv: filteredTag,
              mode: C.mode.CTR,
              padding: C.pad.NoPadding
          });

          return tag.concat(ciphertext.ciphertext);
      },
      decrypt: function(adArray, ciphertext){
          if (!ciphertext && adArray) {
              ciphertext = adArray;
              adArray = [];
          }

          var tag = ext.shiftBytes(ciphertext, 16);
          var filteredTag = ext.bitand(tag, ext.const_nonMSB);

          var plaintext = C.AES.decrypt({ciphertext:ciphertext}, this._ctrKey, {
              iv: filteredTag,
              mode: C.mode.CTR,
              padding: C.pad.NoPadding
          });

          var s2v = S2V.create(this._s2vKey);
          Array.prototype.forEach.call(adArray, function(ad){
              s2v.updateAAD(ad);
          });
          var recoveredTag = s2v.finalize(plaintext);

          if (ext.equals(tag, recoveredTag)) {
              return plaintext;
          } else {
              return false;
          }
      }
  });


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  var WordArray = C.lib.WordArray;
  var crypto = window.crypto;
  var TypedArray = Int32Array;
  if (TypedArray && crypto && crypto.getRandomValues) {
      WordArray.random = function(nBytes){
          var array = new TypedArray(Math.ceil(nBytes / 4));
          crypto.getRandomValues(array);
          return new WordArray.init(
                  [].map.call(array, function(word){
                      return word
                  }),
                  nBytes
          );
      };
  } else {
      console.log("No cryptographically secure randomness source available");
  }


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


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */

  /**
   * Cipher Feedback block mode with segment size parameter according to
   * http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf.
   * The segment size must be a multiple of 32 bit (word size) and not bigger
   * than the block size of the underlying block cipher.
   *
   * Use CryptoJS.mode.CFBb if you want segments as small as 1 bit.
   */

  var CFBw = C.lib.BlockCipherMode.extend();

  CFBw.Encryptor = CFBw.extend({
      processBlock: function(words, offset){
          processBlock.call(this, words, offset, true);
      }
  });

  CFBw.Decryptor = CFBw.extend({
      processBlock: function(words, offset){
          processBlock.call(this, words, offset, false);
      }
  });

  function processBlock(words, offset, encryptor) {
      // Shortcuts
      var self = this;
      var cipher = self._cipher;
      var blockSize = cipher.blockSize; // in words
      var prev = self._prevBlock;
      var segmentSize = cipher.cfg.segmentSize / 32; // in words

      // somehow the wrong indexes are used
      for(var i = 0; i < blockSize/segmentSize; i++) {
          if (!prev) {
              prev = self._iv.slice(0); // clone

              // Remove IV for subsequent blocks
              self._iv = undefined;
          } else {
              prev = prev.slice(segmentSize).concat(self._ct);
          }

          if (!encryptor) {
              self._ct = words.slice(offset + i * segmentSize, offset + i * segmentSize + segmentSize);
          }

          var segKey = prev.slice(0); // clone
          cipher.encryptBlock(segKey, 0);

          // Encrypt segment
          for (var j = 0; j < segmentSize; j++) {
              words[offset + i * segmentSize + j] ^= segKey[j];
          }

          if (encryptor) {
              self._ct = words.slice(offset + i * segmentSize, offset + i * segmentSize + segmentSize);
          }
      }
      self._prevBlock = prev;
  }

  C.mode.CFBw = CFBw;


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  // Shortcuts
  var C_lib = C.lib;
  var Base = C_lib.Base;
  var WordArray = C_lib.WordArray;
  var Hasher = C_lib.Hasher;
  var hasherStore = [];

  var HKDF = C.algo.HKDF = Base.extend({
  	/**
  	 * Initializes a newly created HKDF
  	 *
  	 * @param {Hasher} hasher A hashing function such as CryptoJS.algo.SHA1
  	 * @param {WordArray | String} key The secret key
  	 * @param {WordArray | String} salt Optional non-secret salt value
  	 * @param {boolean} cacheHasherLength Optional flag which determines if
  	 *                  the hasherStore should be used
  	 *
  	 * @example
  	 *
  	 *     var hkdf = CryptoJS.algo.HKDF.create(CryptoJS.algo.SHA1, key);
  	 */
  	init: function(hasher, key, salt, cacheHasherLength){
  		var self = this,
  			filteredHasher = hasherStore.filter(function(h){
  				return h[0] === hasher;
  			});
  		if (filteredHasher.length > 0 && cacheHasherLength) {
  			self._hashLen = filteredHasher[0][1];
  		} else {
  			self._hashLen = Hasher._createHelper(hasher)('').sigBytes;
  			if (cacheHasherLength) {
  				hasherStore.push([hasher, self._hashLen]);
  			}
  		}

  		salt = salt || new WordArray.init([], self._hashLen);

  		self._hmacer = Hasher._createHmacHelper(hasher);
  		self._prk = self._hmacer(key, salt);
  	},

  	extract: function () {
  		return this._prk;
  	},

  	expand: function (outputLength, info) {
  		var previousBlock = new WordArray.init(),
  			result = new WordArray.init(),
  			i,
  			self = this,
  			iterations = Math.ceil(outputLength / self._hashLen);
  		info = info || new WordArray.init();

  		for(i = 1; i <= iterations; i++) {
  			previousBlock = self._hmacer(previousBlock.concat(info).concat(new WordArray.init([i<<24], 1)), self._prk);
  			result.concat(previousBlock);
  		}
  		result.sigBytes = outputLength;
  		result.clamp();
  		return result;
  	}
  });

  /**
   * Directly invokes the HKDF and returns the expanded key material without
   * any of the optional values.
   *
   * @param {Hasher} hasher A hashing function such as CryptoJS.algo.SHA1
   * @param {WordArray} key The key to be used for CMAC
   * @param {integer} outputLength The output length in bytes
   *
   * @returns {WordArray} MAC
   */
  C.HKDF = function(hasher, key, outputLength){
  	return HKDF.create(hasher, key).expand(outputLength);
  };


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
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
  	var i, j, k, x;

  	for (i = 0, j = 0; i < 4; i++, j += 2) {
  		sbox_x.push([]);
  		for (k = 0; k < 256; k++) {
  			x = (sbox[j][k & 0x0f] | sbox[j+1][k>>4] << 4) << (j*4);
  			sbox_x[i][k] = x << 11 | x >>> 21;
  		}
  	}
  }(sbox, sbox_x));

  function f(word)
  {
  	return sbox_x[3][word >>> 24] ^
  		sbox_x[2][(word & 0x00ff0000) >>> 16] ^
  		sbox_x[1][(word & 0x0000ff00) >>>  8] ^
  		sbox_x[0][(word & 0x000000ff)];
  }

  function encrypt_block(l, r, key)
  {
  	var i;
  	l = switch_word_endianness(l);
  	r = switch_word_endianness(r);

  	for (i = 0; i < 23; i += 2) {
  		l ^= f(r + key[i % 8]);
  		r ^= f(l + key[(i+1) % 8]);
  	}

  	for (i = 24; i < 31; i += 2) {
  		l ^= f(r + key[31-i]);
  		r ^= f(l + key[31-(i+1)]);
  	}

  	return [switch_word_endianness(l), switch_word_endianness(r)];
  }

  function decrypt_block(l, r, key)
  {
  	var i;
  	l = switch_word_endianness(l);
  	r = switch_word_endianness(r);

  	for (i = 0; i < 7; i += 2) {
  		l ^= f(r + key[i]);
  		r ^= f(l + key[i+1]);
  	}

  	for (i = 8; i < 31; i += 2) {
  		l ^= f(r + key[(31-i) % 8]);
  		r ^= f(l + key[(31-(i+1)) % 8]);
  	}

  	return [switch_word_endianness(l), switch_word_endianness(r)];
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

  function switch_word_endianness(word) {
  	return word >>> 24 | ((word >>> 8) & 0xff00) |
  		(word & 0xff00) << 8 | (word & 0xff) << 24;
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
  	return words.slice(0, 8).map(switch_word_endianness);
  }

  /**
   * GOST 28147-89 (ГОСТ 28147-89) block cipher algorithm.
   */
  var Gost28147 = C_algo.Gost28147 = BlockCipher.extend({
  	_doReset: function () {
  		this.__ck = check_key(this._key);
  	},

  	encryptBlock: function (M, offset) {
  		var block = encrypt_block(M[offset+1], M[offset], this.__ck)
  		M[offset] = block[0];
  		M[offset+1] = block[1];
  	},

  	decryptBlock: function (M, offset) {
  		var block = decrypt_block(M[offset+1], M[offset], this.__ck)
  		M[offset] = block[0];
  		M[offset+1] = block[1];
  	},

  	blockSize: 64/32,
  	keySize: 256/32
  });

  C.Gost28147 = BlockCipher._createHelper(Gost28147);


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  // port of https://github.com/sftp/gost34.11-2012_stribog

  // Shortcuts
  var CJS = C;
  var C_lib = CJS.lib;
  var WordArray = C_lib.WordArray;
  var BlockCipher = C_lib.BlockCipher;
  var Hasher = C_lib.Hasher;
  var C_algo = CJS.algo;
  var BLOCK_SIZE = 64;

  var sbox = [
  	0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16,
  	0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
  	0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba,
  	0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
  	0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21,
  	0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
  	0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0,
  	0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
  	0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab,
  	0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
  	0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12,
  	0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
  	0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7,
  	0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
  	0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e,
  	0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
  	0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9,
  	0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
  	0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc,
  	0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
  	0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44,
  	0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
  	0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f,
  	0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
  	0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7,
  	0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
  	0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe,
  	0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
  	0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b,
  	0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
  	0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0,
  	0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6
  ];

  var A = [
  	0x8e20faa7, 0x2ba0b470, 0x47107ddd, 0x9b505a38,
  	0xad08b0e0, 0xc3282d1c, 0xd8045870, 0xef14980e,
  	0x6c022c38, 0xf90a4c07, 0x3601161c, 0xf205268d,
  	0x1b8e0b0e, 0x798c13c8, 0x83478b07, 0xb2468764,
  	0xa011d380, 0x818e8f40, 0x5086e740, 0xce47c920,
  	0x2843fd20, 0x67adea10, 0x14aff010, 0xbdd87508,
  	0x0ad97808, 0xd06cb404, 0x05e23c04, 0x68365a02,
  	0x8c711e02, 0x341b2d01, 0x46b60f01, 0x1a83988e,
  	0x90dab52a, 0x387ae76f, 0x486dd415, 0x1c3dfdb9,
  	0x24b86a84, 0x0e90f0d2, 0x125c3542, 0x07487869,
  	0x092e9421, 0x8d243cba, 0x8a174a9e, 0xc8121e5d,
  	0x4585254f, 0x64090fa0, 0xaccc9ca9, 0x328a8950,
  	0x9d4df05d, 0x5f661451, 0xc0a878a0, 0xa1330aa6,
  	0x60543c50, 0xde970553, 0x302a1e28, 0x6fc58ca7,
  	0x18150f14, 0xb9ec46dd, 0x0c84890a, 0xd27623e0,
  	0x0642ca05, 0x693b9f70, 0x0321658c, 0xba93c138,
  	0x86275df0, 0x9ce8aaa8, 0x439da078, 0x4e745554,
  	0xafc0503c, 0x273aa42a, 0xd960281e, 0x9d1d5215,
  	0xe230140f, 0xc0802984, 0x71180a89, 0x60409a42,
  	0xb60c05ca, 0x30204d21, 0x5b068c65, 0x1810a89e,
  	0x456c3488, 0x7a3805b9, 0xac361a44, 0x3d1c8cd2,
  	0x561b0d22, 0x900e4669, 0x2b838811, 0x480723ba,
  	0x9bcf4486, 0x248d9f5d, 0xc3e92243, 0x12c8c1a0,
  	0xeffa11af, 0x0964ee50, 0xf97d86d9, 0x8a327728,
  	0xe4fa2054, 0xa80b329c, 0x727d102a, 0x548b194e,
  	0x39b00815, 0x2acb8227, 0x92580484, 0x15eb419d,
  	0x492c0242, 0x84fbaec0, 0xaa160121, 0x42f35760,
  	0x550b8e9e, 0x21f7a530, 0xa48b474f, 0x9ef5dc18,
  	0x70a6a56e, 0x2440598e, 0x3853dc37, 0x1220a247,
  	0x1ca76e95, 0x091051ad, 0x0edd37c4, 0x8a08a6d8,
  	0x07e09562, 0x4504536c, 0x8d70c431, 0xac02a736,
  	0xc8386296, 0x5601dd1b, 0x641c314b, 0x2b8ee083
  ];

  var C = [
  	[
  		0xb1, 0x08, 0x5b, 0xda, 0x1e, 0xca, 0xda, 0xe9,
  		0xeb, 0xcb, 0x2f, 0x81, 0xc0, 0x65, 0x7c, 0x1f,
  		0x2f, 0x6a, 0x76, 0x43, 0x2e, 0x45, 0xd0, 0x16,
  		0x71, 0x4e, 0xb8, 0x8d, 0x75, 0x85, 0xc4, 0xfc,
  		0x4b, 0x7c, 0xe0, 0x91, 0x92, 0x67, 0x69, 0x01,
  		0xa2, 0x42, 0x2a, 0x08, 0xa4, 0x60, 0xd3, 0x15,
  		0x05, 0x76, 0x74, 0x36, 0xcc, 0x74, 0x4d, 0x23,
  		0xdd, 0x80, 0x65, 0x59, 0xf2, 0xa6, 0x45, 0x07
  	], [
  		0x6f, 0xa3, 0xb5, 0x8a, 0xa9, 0x9d, 0x2f, 0x1a,
  		0x4f, 0xe3, 0x9d, 0x46, 0x0f, 0x70, 0xb5, 0xd7,
  		0xf3, 0xfe, 0xea, 0x72, 0x0a, 0x23, 0x2b, 0x98,
  		0x61, 0xd5, 0x5e, 0x0f, 0x16, 0xb5, 0x01, 0x31,
  		0x9a, 0xb5, 0x17, 0x6b, 0x12, 0xd6, 0x99, 0x58,
  		0x5c, 0xb5, 0x61, 0xc2, 0xdb, 0x0a, 0xa7, 0xca,
  		0x55, 0xdd, 0xa2, 0x1b, 0xd7, 0xcb, 0xcd, 0x56,
  		0xe6, 0x79, 0x04, 0x70, 0x21, 0xb1, 0x9b, 0xb7
  	], [
  		0xf5, 0x74, 0xdc, 0xac, 0x2b, 0xce, 0x2f, 0xc7,
  		0x0a, 0x39, 0xfc, 0x28, 0x6a, 0x3d, 0x84, 0x35,
  		0x06, 0xf1, 0x5e, 0x5f, 0x52, 0x9c, 0x1f, 0x8b,
  		0xf2, 0xea, 0x75, 0x14, 0xb1, 0x29, 0x7b, 0x7b,
  		0xd3, 0xe2, 0x0f, 0xe4, 0x90, 0x35, 0x9e, 0xb1,
  		0xc1, 0xc9, 0x3a, 0x37, 0x60, 0x62, 0xdb, 0x09,
  		0xc2, 0xb6, 0xf4, 0x43, 0x86, 0x7a, 0xdb, 0x31,
  		0x99, 0x1e, 0x96, 0xf5, 0x0a, 0xba, 0x0a, 0xb2
  	], [
  		0xef, 0x1f, 0xdf, 0xb3, 0xe8, 0x15, 0x66, 0xd2,
  		0xf9, 0x48, 0xe1, 0xa0, 0x5d, 0x71, 0xe4, 0xdd,
  		0x48, 0x8e, 0x85, 0x7e, 0x33, 0x5c, 0x3c, 0x7d,
  		0x9d, 0x72, 0x1c, 0xad, 0x68, 0x5e, 0x35, 0x3f,
  		0xa9, 0xd7, 0x2c, 0x82, 0xed, 0x03, 0xd6, 0x75,
  		0xd8, 0xb7, 0x13, 0x33, 0x93, 0x52, 0x03, 0xbe,
  		0x34, 0x53, 0xea, 0xa1, 0x93, 0xe8, 0x37, 0xf1,
  		0x22, 0x0c, 0xbe, 0xbc, 0x84, 0xe3, 0xd1, 0x2e
  	], [
  		0x4b, 0xea, 0x6b, 0xac, 0xad, 0x47, 0x47, 0x99,
  		0x9a, 0x3f, 0x41, 0x0c, 0x6c, 0xa9, 0x23, 0x63,
  		0x7f, 0x15, 0x1c, 0x1f, 0x16, 0x86, 0x10, 0x4a,
  		0x35, 0x9e, 0x35, 0xd7, 0x80, 0x0f, 0xff, 0xbd,
  		0xbf, 0xcd, 0x17, 0x47, 0x25, 0x3a, 0xf5, 0xa3,
  		0xdf, 0xff, 0x00, 0xb7, 0x23, 0x27, 0x1a, 0x16,
  		0x7a, 0x56, 0xa2, 0x7e, 0xa9, 0xea, 0x63, 0xf5,
  		0x60, 0x17, 0x58, 0xfd, 0x7c, 0x6c, 0xfe, 0x57
  	], [
  		0xae, 0x4f, 0xae, 0xae, 0x1d, 0x3a, 0xd3, 0xd9,
  		0x6f, 0xa4, 0xc3, 0x3b, 0x7a, 0x30, 0x39, 0xc0,
  		0x2d, 0x66, 0xc4, 0xf9, 0x51, 0x42, 0xa4, 0x6c,
  		0x18, 0x7f, 0x9a, 0xb4, 0x9a, 0xf0, 0x8e, 0xc6,
  		0xcf, 0xfa, 0xa6, 0xb7, 0x1c, 0x9a, 0xb7, 0xb4,
  		0x0a, 0xf2, 0x1f, 0x66, 0xc2, 0xbe, 0xc6, 0xb6,
  		0xbf, 0x71, 0xc5, 0x72, 0x36, 0x90, 0x4f, 0x35,
  		0xfa, 0x68, 0x40, 0x7a, 0x46, 0x64, 0x7d, 0x6e
  	], [
  		0xf4, 0xc7, 0x0e, 0x16, 0xee, 0xaa, 0xc5, 0xec,
  		0x51, 0xac, 0x86, 0xfe, 0xbf, 0x24, 0x09, 0x54,
  		0x39, 0x9e, 0xc6, 0xc7, 0xe6, 0xbf, 0x87, 0xc9,
  		0xd3, 0x47, 0x3e, 0x33, 0x19, 0x7a, 0x93, 0xc9,
  		0x09, 0x92, 0xab, 0xc5, 0x2d, 0x82, 0x2c, 0x37,
  		0x06, 0x47, 0x69, 0x83, 0x28, 0x4a, 0x05, 0x04,
  		0x35, 0x17, 0x45, 0x4c, 0xa2, 0x3c, 0x4a, 0xf3,
  		0x88, 0x86, 0x56, 0x4d, 0x3a, 0x14, 0xd4, 0x93
  	], [
  		0x9b, 0x1f, 0x5b, 0x42, 0x4d, 0x93, 0xc9, 0xa7,
  		0x03, 0xe7, 0xaa, 0x02, 0x0c, 0x6e, 0x41, 0x41,
  		0x4e, 0xb7, 0xf8, 0x71, 0x9c, 0x36, 0xde, 0x1e,
  		0x89, 0xb4, 0x44, 0x3b, 0x4d, 0xdb, 0xc4, 0x9a,
  		0xf4, 0x89, 0x2b, 0xcb, 0x92, 0x9b, 0x06, 0x90,
  		0x69, 0xd1, 0x8d, 0x2b, 0xd1, 0xa5, 0xc4, 0x2f,
  		0x36, 0xac, 0xc2, 0x35, 0x59, 0x51, 0xa8, 0xd9,
  		0xa4, 0x7f, 0x0d, 0xd4, 0xbf, 0x02, 0xe7, 0x1e
  	], [
  		0x37, 0x8f, 0x5a, 0x54, 0x16, 0x31, 0x22, 0x9b,
  		0x94, 0x4c, 0x9a, 0xd8, 0xec, 0x16, 0x5f, 0xde,
  		0x3a, 0x7d, 0x3a, 0x1b, 0x25, 0x89, 0x42, 0x24,
  		0x3c, 0xd9, 0x55, 0xb7, 0xe0, 0x0d, 0x09, 0x84,
  		0x80, 0x0a, 0x44, 0x0b, 0xdb, 0xb2, 0xce, 0xb1,
  		0x7b, 0x2b, 0x8a, 0x9a, 0xa6, 0x07, 0x9c, 0x54,
  		0x0e, 0x38, 0xdc, 0x92, 0xcb, 0x1f, 0x2a, 0x60,
  		0x72, 0x61, 0x44, 0x51, 0x83, 0x23, 0x5a, 0xdb
  	], [
  		0xab, 0xbe, 0xde, 0xa6, 0x80, 0x05, 0x6f, 0x52,
  		0x38, 0x2a, 0xe5, 0x48, 0xb2, 0xe4, 0xf3, 0xf3,
  		0x89, 0x41, 0xe7, 0x1c, 0xff, 0x8a, 0x78, 0xdb,
  		0x1f, 0xff, 0xe1, 0x8a, 0x1b, 0x33, 0x61, 0x03,
  		0x9f, 0xe7, 0x67, 0x02, 0xaf, 0x69, 0x33, 0x4b,
  		0x7a, 0x1e, 0x6c, 0x30, 0x3b, 0x76, 0x52, 0xf4,
  		0x36, 0x98, 0xfa, 0xd1, 0x15, 0x3b, 0xb6, 0xc3,
  		0x74, 0xb4, 0xc7, 0xfb, 0x98, 0x45, 0x9c, 0xed
  	], [
  		0x7b, 0xcd, 0x9e, 0xd0, 0xef, 0xc8, 0x89, 0xfb,
  		0x30, 0x02, 0xc6, 0xcd, 0x63, 0x5a, 0xfe, 0x94,
  		0xd8, 0xfa, 0x6b, 0xbb, 0xeb, 0xab, 0x07, 0x61,
  		0x20, 0x01, 0x80, 0x21, 0x14, 0x84, 0x66, 0x79,
  		0x8a, 0x1d, 0x71, 0xef, 0xea, 0x48, 0xb9, 0xca,
  		0xef, 0xba, 0xcd, 0x1d, 0x7d, 0x47, 0x6e, 0x98,
  		0xde, 0xa2, 0x59, 0x4a, 0xc0, 0x6f, 0xd8, 0x5d,
  		0x6b, 0xca, 0xa4, 0xcd, 0x81, 0xf3, 0x2d, 0x1b
  	], [
  		0x37, 0x8e, 0xe7, 0x67, 0xf1, 0x16, 0x31, 0xba,
  		0xd2, 0x13, 0x80, 0xb0, 0x04, 0x49, 0xb1, 0x7a,
  		0xcd, 0xa4, 0x3c, 0x32, 0xbc, 0xdf, 0x1d, 0x77,
  		0xf8, 0x20, 0x12, 0xd4, 0x30, 0x21, 0x9f, 0x9b,
  		0x5d, 0x80, 0xef, 0x9d, 0x18, 0x91, 0xcc, 0x86,
  		0xe7, 0x1d, 0xa4, 0xaa, 0x88, 0xe1, 0x28, 0x52,
  		0xfa, 0xf4, 0x17, 0xd5, 0xd9, 0xb2, 0x1b, 0x99,
  		0x48, 0xbc, 0x92, 0x4a, 0xf1, 0x1b, 0xd7, 0x20
  	]
  ];

  function addmod512(dst, src, add)
  {
  	var i,
  		overrun = 0;

  	for (i = BLOCK_SIZE; i-- > 0;) {
  		overrun = (src[i] + add[i] + (overrun >>> 8)) | 0;
  		dst[i] = overrun & 0xFF;
  	}
  }

  function addmod512_u32(dst, src, add)
  {
  	var i;

  	for (i = BLOCK_SIZE; i-- > 0;) {
  		add = (src[i] + add) | 0;
  		dst[i] = add & 0xFF;
  		add >>>= 8;
  	}
  }

  function xor512(dst, a, b)
  {
  	var i;

  	for (i = 0; i < BLOCK_SIZE; i++) {
  		dst[i] = a[i] ^ b[i];
  	}
  }

  function S(vect)
  {
  	var i;

  	for (i = 0; i < BLOCK_SIZE; i++) {
  		vect[i] = sbox[vect[i]];
  	}
  }

  function cpy(dst, src, len, offset) {
  	len = len || src.length;
  	offset = offset || 0;
  	for(var i = offset; i < (offset+len); i++) {
  		if (dst.length <= (i-offset))
  			dst.push(src[i] | 0);
  		else
  			dst = src[i] | 0;
  	}
  	return dst;
  }

  function LP(vect)
  {
  	var i, j, k, tmp = [], c0, c1;

  	cpy(tmp, vect, 64);

  	/*
  	 * subvectors of 512-bit vector (64*8 bits)
  	 * an subvector is start at [j*8], its componenst placed
  	 * with step of 8 bytes (due to this function is composition
  	 * of P and L) and have length of 64 bits (8*8 bits)
  	 */
  	for (i = 0; i < 8; i++) {
  		c0 = 0;
  		c1 = 0;

  		/*
  		 * 8-bit components of 64-bit subvectors
  		 * components is placed at [j*8+i]
  		 */
  		for (j = 0; j < 8; j++) {

  			/* bit index of current 8-bit component */
  			for (k = 0; k < 8; k++) {

  				/* check if current bit is set */
  				if (tmp[j*8+i] & 0x80 >>> k){
  					c0 ^= A[2*(j*8+k)];
  					c1 ^= A[2*(j*8+k)+1];
  				}
  			}
  		}

  		for (j = 0; j < 8; j++) {
  			if (j < 4) {
  				vect[i*8+j] = (c0 >>> (3 - j) * 8) & 0xFF;
  			} else {
  				vect[i*8+j] = (c1 >>> (7 - j) * 8) & 0xFF;
  			}
  		}
  	}
  }

  function E(dst, k, m)
  {
  	var i,
  		K = [];

  	cpy(K, k, BLOCK_SIZE);

  	xor512(dst, K, m);

  	for (i = 1; i < 13; i++) {
  		S(dst);
  		LP(dst);

  		/* next K */
  		xor512(K, K, C[i-1]);

  		S(K);
  		LP(K);

  		xor512(dst, K, dst);
  	}
  }

  function g_N(h, N, m)
  {
  	var hash = [];
  	cpy(hash, h, BLOCK_SIZE);

  	xor512(h, h, N);

  	S(h);
  	LP(h);

  	E(h, h, m);

  	xor512(h, h, hash);
  	xor512(h, h, m);
  }

  function g_0(h, m)
  {
  	var hash = [];
  	cpy(hash, h, BLOCK_SIZE);

  	S(h);
  	LP(h);

  	E(h, h, m);

  	xor512(h, h, hash);
  	xor512(h, h, m);
  }

  function stribog(message, len, is256)
  {
  	var i,
  		m,
  		padding,
  		h = [],
  		N = [],
  		S = [];
  	for(i = 0; i < BLOCK_SIZE; i++) {
  		h.push(is256 ? 1 : 0);
  		N.push(0);
  		S.push(0);
  	}

  	while (len >= BLOCK_SIZE) {
  		m = [];
  		cpy(m, message, BLOCK_SIZE, len - BLOCK_SIZE);

  		g_N(h, N, m);

  		len -= BLOCK_SIZE;

  		addmod512_u32(N, N, BLOCK_SIZE * 8);
  		addmod512(S, S, m);
  	}

  	padding = BLOCK_SIZE - len;

  	if (padding > 0) {
  		m = [];
  		cpy(m, message, len);
  		m.unshift(1);
  		for(i = 0; i < (padding - 1); i++) {
  			m.unshift(0);
  		}
  	}

  	g_N(h, N, m);

  	addmod512_u32(N, N, len*8);
  	addmod512(S, S, m);

  	g_0(h, N);
  	g_0(h, S);

  	return h.slice(0, is256 ? 32 : 64)
  }

  /**
   * Combine bytes into words (4 ints into one int)
   */
  function from_u8_to_u32(u8_bytes){
  	var words = [], i;
  	for(i = 0; i < u8_bytes.length; i++) {
  		if (i % 4 === 0) {
  			words.push(0);
  		}

  		words[(i / 4) | 0] ^= u8_bytes[i] << ((3 - i%4)*8);
  	}
  	return words;
  }

  /**
   * Split words into bytes (one into into 4 ints)
   */
  function from_u32_to_u8(u32_words, sigBytes){
  	var bytes = [], i;
  	for(i = 0; i < sigBytes; i++) {
  		bytes.push((u32_words[(i / 4) | 0] >>> ((3 - i%4)*8)) & 0xff);
  	}
  	return bytes;
  }

  var Streebog256 = C_algo.Streebog256 = Hasher.extend({
  	_doReset: function () {
  		this._streebogCache = new WordArray.init();
  	},

  	_doProcessBlock: function (M, offset) {
  		var self = this,
  			cache = self._streebogCache,
  			i;
  		for(i = 0; i < self.blockSize; i++) {
  			cache.words.push(M[i + offset]);
  			cache.sigBytes += 4;
  		}
  	},

  	_doFinalize: function () {
  		// Shortcuts
  		var self = this;
  		var data = self._data;
  		var dataWords = data.words;

  		var cache = self._streebogCache;
  		var cacheWords = cache.words;
  		var messageBytes;
  		var i;
  		var hashBytes;
  		var hash;

  		// put the rest into cache
  		for(i = 0; i < dataWords.length; i++) {
  			cacheWords.push(dataWords[i]);
  		}
  		cache.sigBytes += data.sigBytes;

  		// split words into bytes (one into into 4 ints)
  		messageBytes = from_u32_to_u8(cacheWords, cache.sigBytes);

  		// hash
  		hashBytes = stribog(messageBytes, messageBytes.length, self.outputSize === 256);

  		// combine bytes into words (4 ints into one int)
  		hash = new WordArray.init(from_u8_to_u32(hashBytes));

  		// Hash final blocks
  		//self._process();

  		// Return final computed hash
  		return hash;
  	},

  	clone: function () {
  		var clone = Hasher.clone.call(this);
  		clone._hash = this._hash.clone();

  		return clone;
  	},

  	outputSize: 256
  });

  var Streebog512 = C_algo.Streebog512 = Streebog256.extend({
  	outputSize: 512
  });

  CJS.Streebog256 = Hasher._createHelper(Streebog256);
  CJS.Streebog512 = Hasher._createHelper(Streebog512);


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  C.enc.Bin = {
      stringify: function (wordArray) {
          // Shortcuts
          var words = wordArray.words;
          var sigBytes = wordArray.sigBytes;

          // Convert
          var binChars = [];
          for (var i = 0; i < sigBytes; i++) {
              var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;

              for(var j = 7; j >= 0; j--) {
                  binChars.push((bite >>> j & 0x01).toString(2));
              }
          }

          return binChars.join('');
      },
      parse: function (binStr) {
          var words = [ 0 ];
          var currentBit = 31;
          var bits = 0;
          for(var i = 0; i < binStr.length; i++) {
              var c = binStr[i];
              if (c !== "0" && c !== "1") {
                  // skip non-encoding characters such as spaces and such
                  continue;
              }
              words[words.length-1] += (parseInt(c) << currentBit);
              currentBit--;
              bits++;
              if (currentBit < 0) {
                  currentBit = 31;
                  words.push(0);
              }
          }
          return new C.lib.WordArray.init(words, Math.ceil(bits/8));
      }
  };


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  // put on ext property in CryptoJS
  var ext;
  if (!C.hasOwnProperty("ext")) {
      ext = C.ext = {};
  } else {
      ext = C.ext;
  }

  /**
   * Shifts the array by n bits to the left. Zero bits are added as the
   * least significant bits. This operation modifies the current array.
   *
   * @param {WordArray} wordArray WordArray to work on
   * @param {int} n Bits to shift by
   *
   * @returns the WordArray that was passed in
   */
  ext.bitshift = function(wordArray, n){
      var carry = 0,
          words = wordArray.words,
          wres,
          skipped = 0,
          carryMask;
      if (n > 0) {
          while(n > 31) {
              // delete first element:
              words.splice(0, 1);

              // add `0` word to the back
              words.push(0);

              n -= 32;
              skipped++;
          }
          if (n == 0) {
              // 1. nothing to shift if the shift amount is on a word boundary
              // 2. This has to be done, because the following algorithm computes
              // wrong values only for n==0
              return carry;
          }
          for(var i = words.length - skipped - 1; i >= 0; i--) {
              wres = words[i];
              words[i] <<= n;
              words[i] |= carry;
              carry = wres >>> (32 - n);
          }
      } else if (n < 0) {
          while(n < -31) {
              // insert `0` word to the front:
              words.splice(0, 0, 0);

              // remove last element:
              words.length--;

              n += 32;
              skipped++;
          }
          if (n == 0) {
              // nothing to shift if the shift amount is on a word boundary
              return carry;
          }
          n = -n;
          carryMask = (1 << n) - 1;
          for(var i = skipped; i < words.length; i++) {
              wres = words[i] & carryMask;
              words[i] >>>= n;
              words[i] |= carry;
              carry = wres << (32 - n);
          }
      }
      return carry;
  };

  /**
   * Negates all bits in the WordArray. This manipulates the given array.
   *
   * @param {WordArray} wordArray WordArray to work on
   *
   * @returns the WordArray that was passed in
   */
  ext.neg = function(wordArray){
      var words = wordArray.words;
      for(var i = 0; i < words.length; i++) {
          words[i] = ~words[i];
      }
      return wordArray;
  };

  /**
   * Applies XOR on both given word arrays and returns a third resulting
   * WordArray. The initial word arrays must have the same length
   * (significant bytes).
   *
   * @param {WordArray} wordArray1 WordArray
   * @param {WordArray} wordArray2 WordArray
   *
   * @returns first passed WordArray (modified)
   */
  ext.xor = function(wordArray1, wordArray2){
      for(var i = 0; i < wordArray1.words.length; i++) {
          wordArray1.words[i] ^= wordArray2.words[i];
      }
      return wordArray1;
  };

  /**
   * Logical AND between the two passed arrays. Both arrays must have the
   * same length.
   *
   * @param {WordArray} arr1 Array 1
   * @param {WordArray} arr2 Array 2
   *
   * @returns new WordArray
   */
  ext.bitand = function(arr1, arr2){
      var newArr = arr1.clone(),
          tw = newArr.words,
          ow = arr2.words;
      for(var i = 0; i < tw.length; i++) {
          tw[i] &= ow[i];
      }
      return newArr;
  };


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */

  /**
   * Cipher Feedback block mode with segment size parameter according to
   * http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf.
   * The segment size can be anything from 1 bit up to the block size of the
   * underlying block cipher.
   *
   * Current limitation: only segment sizes that divide the block size evenly
   * are supported.
   */
  var CFBb = C.lib.BlockCipherMode.extend(),
      WordArray = C.lib.WordArray, // shortcut
      bitshift = C.ext.bitshift,
      neg = C.ext.neg;

  CFBb.Encryptor = CFBb.extend({
      processBlock: function(words, offset){
          processBlock.call(this, words, offset, true);
      }
  });

  CFBb.Decryptor = CFBb.extend({
      processBlock: function(words, offset){
          processBlock.call(this, words, offset, false);
      }
  });

  function processBlock(words, offset, encryptor) {
      // Shortcuts
      var self = this;
      var cipher = self._cipher;
      var blockSize = cipher.blockSize * 32; // in bits
      var prev = self._prevBlock;
      var segmentSize = cipher.cfg.segmentSize; // in bits
      var i, j;
      var currentPosition;

      // Create a bit mask that has a comtinuous slice of bits set that is as big as the segment
      var fullSegmentMask = [];
      for(i = 31; i < segmentSize; i += 32) {
          fullSegmentMask.push(0xffffffff);
      }
      // `s` most signiicant bits are set:
      fullSegmentMask.push(((1 << segmentSize) - 1) << (32 - segmentSize));
      for(i = fullSegmentMask.length; i < words.length; i++) {
          fullSegmentMask.push(0);
      }

      fullSegmentMask = new WordArray.init(fullSegmentMask);

      // some helper variables
      var slidingSegmentMask = fullSegmentMask.clone(),
          slidingSegmentMaskShifted = slidingSegmentMask.clone(),
          slidingNegativeSegmentMask,
          prevCT;

      // shift the mask according to the current offset
      bitshift(slidingSegmentMaskShifted, -offset * 32);

      for(i = 0; i < blockSize/segmentSize; i++) {
          if (!prev) {
              prev = self._iv.slice(0); // clone

              // Remove IV for subsequent blocks
              self._iv = undefined;
          } else {
              // Prepare the iteration by concatenating the unencrypted part of the previous block and the previous ciphertext

              prev = new WordArray.init(prev);
              bitshift(prev, segmentSize);
              prev = prev.words;
              previousCiphertextSegment = self._ct;

              // fill previous ciphertext up to the block size
              while(previousCiphertextSegment.length < blockSize / 32) {
                  previousCiphertextSegment.push(0);
              }
              previousCiphertextSegment = new WordArray.init(previousCiphertextSegment);

              // move to the back
              bitshift(previousCiphertextSegment, -blockSize + segmentSize);

              // put together
              for (var j = 0; j < prev.length; j++) {
                  prev[j] |= previousCiphertextSegment.words[j];
              }
          }

          currentPosition = offset * 32 + i * segmentSize;

          // move segment in question to the front of the array
          var plaintextSlice = new WordArray.init(words.slice(0));
          bitshift(plaintextSlice, currentPosition);

          if (!encryptor) {
              self._ct = plaintextSlice.words.slice(0, Math.ceil(segmentSize / 32));
          }

          var segKey = prev.slice(0); // clone
          cipher.encryptBlock(segKey, 0);

          // Encrypt segment
          for (j = 0; j < Math.ceil(segmentSize / 32); j++) {
              plaintextSlice.words[j] ^= segKey[j];
          }

          // Filter only the current segment
          for (j = 0; j < plaintextSlice.words.length; j++) {
              plaintextSlice.words[j] &= fullSegmentMask.words[j];
          }

          if (encryptor) {
              self._ct = plaintextSlice.words.slice(0, Math.ceil(segmentSize / 32));
          }

          // remove the segment from the plaintext array
          slidingNegativeSegmentMask = neg(slidingSegmentMaskShifted.clone());
          for (j = 0; j < words.length; j++) {
              words[j] &= slidingNegativeSegmentMask.words[j];
          }

          // move filtered ciphertext segment to back to the correct place
          bitshift(plaintextSlice, -currentPosition);

          // add filtered ciphertext segment to the plaintext/ciphertext array
          for (j = 0; j < words.length; j++) {
              words[j] |= plaintextSlice.words[j];
          }

          // shift the segment mask further along
          bitshift(slidingSegmentMask, -segmentSize);
          bitshift(slidingSegmentMaskShifted, -segmentSize);
      }
      self._prevBlock = prev;
  }

  C.mode.CFBb = CFBb;


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  // put on ext property in CryptoJS
  var ext;
  if (!C.hasOwnProperty("ext")) {
      ext = C.ext = {};
  } else {
      ext = C.ext;
  }

  // Shortcuts
  var Base = C.lib.Base;
  var WordArray = C.lib.WordArray;

  // Constants
  ext.const_Zero = new WordArray.init([0x00000000, 0x00000000, 0x00000000, 0x00000000]);
  ext.const_One = new WordArray.init([0x00000000, 0x00000000, 0x00000000, 0x00000001]);
  ext.const_Rb = new WordArray.init([0x00000000, 0x00000000, 0x00000000, 0x00000087]); // 00..0010000111
  ext.const_Rb_Shifted = new WordArray.init([0x80000000, 0x00000000, 0x00000000, 0x00000043]); // 100..001000011
  ext.const_nonMSB = new WordArray.init([0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF]); // 1^64 || 0^1 || 1^31 || 0^1 || 1^31

  /**
   * Looks into the object to see if it is a WordArray.
   *
   * @param obj Some object
   *
   * @returns {boolean}

   */
  ext.isWordArray = function(obj) {
      return obj && typeof obj.clamp === "function" && typeof obj.concat === "function" && typeof obj.words === "array";
  }

  /**
   * This padding is a 1 bit followed by as many 0 bits as needed to fill
   * up the block. This implementation doesn't work on bits directly,
   * but on bytes. Therefore the granularity is much bigger.
   */
  C.pad.OneZeroPadding = {
      pad: function (data, blocksize) {
          // Shortcut
          var blockSizeBytes = blocksize * 4;

          // Count padding bytes
          var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

          // Create padding
          var paddingWords = [];
          for (var i = 0; i < nPaddingBytes; i += 4) {
              var paddingWord = 0x00000000;
              if (i === 0) {
                  paddingWord = 0x80000000;
              }
              paddingWords.push(paddingWord);
          }
          var padding = new WordArray.init(paddingWords, nPaddingBytes);

          // Add padding
          data.concat(padding);
      },
      unpad: function () {
          // TODO: implement
      }
  };

  /**
   * No padding is applied. This is necessary for streaming cipher modes
   * like CTR.
   */
  C.pad.NoPadding = {
      pad: function () {},
      unpad: function () {}
  };

  /**
   * Returns the n leftmost bytes of the WordArray.
   *
   * @param {WordArray} wordArray WordArray to work on
   * @param {int} n Bytes to retrieve
   *
   * @returns new WordArray
   */
  ext.leftmostBytes = function(wordArray, n){
      var lmArray = wordArray.clone();
      lmArray.sigBytes = n;
      lmArray.clamp();
      return lmArray;
  };

  /**
   * Returns the n rightmost bytes of the WordArray.
   *
   * @param {WordArray} wordArray WordArray to work on
   * @param {int} n Bytes to retrieve (must be positive)
   *
   * @returns new WordArray
   */
  ext.rightmostBytes = function(wordArray, n){
      wordArray.clamp();
      var wordSize = 32;
      var rmArray = wordArray.clone();
      var bitsToShift = (rmArray.sigBytes - n) * 8;
      if (bitsToShift >= wordSize) {
          var popCount = Math.floor(bitsToShift/wordSize);
          bitsToShift -= popCount * wordSize;
          rmArray.words.splice(0, popCount);
          rmArray.sigBytes -= popCount * wordSize / 8;
      }
      if (bitsToShift > 0) {
          ext.bitshift(rmArray, bitsToShift);
          rmArray.sigBytes -= bitsToShift / 8;
      }
      return rmArray;
  };

  /**
   * Returns the n rightmost words of the WordArray. It assumes
   * that the current WordArray has at least n words.
   *
   * @param {WordArray} wordArray WordArray to work on
   * @param {int} n Words to retrieve (must be positive)
   *
   * @returns popped words as new WordArray
   */
  ext.popWords = function(wordArray, n){
      var left = wordArray.words.splice(0, n);
      wordArray.sigBytes -= n * 4;
      return new WordArray.init(left);
  };

  /**
   * Shifts the array to the left and returns the shifted dropped elements
   * as WordArray. The initial WordArray must contain at least n bytes and
   * they have to be significant.
   *
   * @param {WordArray} wordArray WordArray to work on (is modified)
   * @param {int} n Bytes to shift (must be positive, default 16)
   *
   * @returns new WordArray
   */
  ext.shiftBytes = function(wordArray, n){
      n = n || 16;
      var r = n % 4;
      n -= r;

      var shiftedArray = new WordArray.init();
      for(var i = 0; i < n; i += 4) {
          shiftedArray.words.push(wordArray.words.shift());
          wordArray.sigBytes -= 4;
          shiftedArray.sigBytes += 4;
      }
      if (r > 0) {
          shiftedArray.words.push(wordArray.words[0]);
          shiftedArray.sigBytes += r;

          ext.bitshift(wordArray, r * 8);
          wordArray.sigBytes -= r;
      }
      return shiftedArray;
  };

  /**
   * XORs arr2 to the end of arr1 array. This doesn't modify the current
   * array aside from clamping.
   *
   * @param {WordArray} arr1 Bigger array
   * @param {WordArray} arr2 Smaller array to be XORed to the end
   *
   * @returns new WordArray
   */
  ext.xorendBytes = function(arr1, arr2){
      // TODO: more efficient
      return ext.leftmostBytes(arr1, arr1.sigBytes-arr2.sigBytes)
              .concat(ext.xor(ext.rightmostBytes(arr1, arr2.sigBytes), arr2));
  };

  /**
   * Doubling operation on a 128-bit value. This operation modifies the
   * passed array.
   *
   * @param {WordArray} wordArray WordArray to work on
   *
   * @returns passed WordArray
   */
  ext.dbl = function(wordArray){
      var carry = ext.msb(wordArray);
      ext.bitshift(wordArray, 1);
      ext.xor(wordArray, carry === 1 ? ext.const_Rb : ext.const_Zero);
      return wordArray;
  };

  /**
   * Inverse operation on a 128-bit value. This operation modifies the
   * passed array.
   *
   * @param {WordArray} wordArray WordArray to work on
   *
   * @returns passed WordArray
   */
  ext.inv = function(wordArray){
      var carry = wordArray.words[4] & 1;
      ext.bitshift(wordArray, -1);
      ext.xor(wordArray, carry === 1 ? ext.const_Rb_Shifted : ext.const_Zero);
      return wordArray;
  };

  /**
   * Check whether the word arrays are equal.
   *
   * @param {WordArray} arr1 Array 1
   * @param {WordArray} arr2 Array 2
   *
   * @returns boolean
   */
  ext.equals = function(arr1, arr2){
      if (!arr2 || !arr2.words || arr1.sigBytes !== arr2.sigBytes) {
          return false;
      }
      arr1.clamp();
      arr2.clamp();
      var equal = 0;
      for(var i = 0; i < arr1.words.length; i++) {
          equal |= arr1.words[i] ^ arr2.words[i];
      }
      return equal === 0;
  };

  /**
   * Retrieves the most significant bit of the WordArray as an Integer.
   *
   * @param {WordArray} arr
   *
   * @returns Integer
   */
  ext.msb = function(arr) {
      return arr.words[0] >>> 31;
  }


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  // Shortcuts
  var Base = C.lib.Base;
  var WordArray = C.lib.WordArray;
  var AES = C.algo.AES;
  var ext = C.ext;
  var OneZeroPadding = C.pad.OneZeroPadding;


  var CMAC = C.algo.CMAC = Base.extend({
      /**
       * Initializes a newly created CMAC
       *
       * @param {WordArray} key The secret key
       *
       * @example
       *
       *     var cmacer = CryptoJS.algo.CMAC.create(key);
       */
      init: function(key){
          // generate sub keys...
          this._aes = AES.createEncryptor(key, { iv: new WordArray.init(), padding: C.pad.NoPadding });

          // Step 1
          var L = this._aes.finalize(ext.const_Zero);

          // Step 2
          var K1 = L.clone();
          ext.dbl(K1);

          // Step 3
          if (!this._isTwo) {
              var K2 = K1.clone();
              ext.dbl(K2);
          } else {
              var K2 = L.clone();
              ext.inv(K2);
          }

          this._K1 = K1;
          this._K2 = K2;

          this._const_Bsize = 16;

          this.reset();
      },

      reset: function () {
          this._x = ext.const_Zero.clone();
          this._counter = 0;
          this._buffer = new WordArray.init();
      },

      update: function (messageUpdate) {
          if (!messageUpdate) {
              return this;
          }

          // Shortcuts
          var buffer = this._buffer;
          var bsize = this._const_Bsize;

          if (typeof messageUpdate === "string") {
              messageUpdate = C.enc.Utf8.parse(messageUpdate);
          }

          buffer.concat(messageUpdate);

          while(buffer.sigBytes > bsize){
              var M_i = ext.shiftBytes(buffer, bsize);
              ext.xor(this._x, M_i);
              this._x.clamp();
              this._aes.reset();
              this._x = this._aes.finalize(this._x);
              this._counter++;
          }

          // Chainable
          return this;
      },

      finalize: function (messageUpdate) {
          this.update(messageUpdate);

          // Shortcuts
          var buffer = this._buffer;
          var bsize = this._const_Bsize;

          var M_last = buffer.clone();
          if (buffer.sigBytes === bsize) {
              ext.xor(M_last, this._K1);
          } else {
              OneZeroPadding.pad(M_last, bsize/4);
              ext.xor(M_last, this._K2);
          }

          ext.xor(M_last, this._x);

          this.reset(); // Can be used immediately afterwards

          this._aes.reset();
          return this._aes.finalize(M_last);
      },

      _isTwo: false
  });

  /**
   * Directly invokes the CMAC and returns the calculated MAC.
   *
   * @param {WordArray} key The key to be used for CMAC
   * @param {WordArray|string} message The data to be MAC'ed (either WordArray or UTF-8 encoded string)
   *
   * @returns {WordArray} MAC
   */
  C.CMAC = function(key, message){
      return CMAC.create(key).finalize(message);
  };

  C.algo.OMAC1 = CMAC;
  C.algo.OMAC2 = CMAC.extend({
      _isTwo: true
  });


  /*
   * The MIT License (MIT)
   *
   * Copyright (c) 2015 artjomb
   */
  // Shortcuts
  var Base = C.lib.Base;
  var WordArray = C.lib.WordArray;
  var AES = C.algo.AES;
  var ext = C.ext;
  var CMAC = C.algo.CMAC;
  var zero = new WordArray.init([0x0, 0x0, 0x0, 0x0]);
  var one = new WordArray.init([0x0, 0x0, 0x0, 0x1]);
  var two = new WordArray.init([0x0, 0x0, 0x0, 0x2]);
  var blockLength = 16;

  var EAX = C.EAX = Base.extend({
      /**
       * Initializes the key of the cipher.
       *
       * @param {WordArray} key Key to be used for CMAC and CTR
       * @param {object} options Additonal options to tweak the encryption:
       *        splitKey - If true then the first half of the passed key will be
       *                   the CMAC key and the second half the CTR key
       *        tagLength - Length of the tag in bytes (for created tag and expected tag)
       */
      init: function(key, options){
          var macKey;
          if (options && options.splitKey) {
              var len = Math.floor(key.sigBytes / 2);
              macKey = ext.shiftBytes(key, len);
          } else {
              macKey = key.clone();
          }
          this._ctrKey = key;
          this._mac = CMAC.create(macKey);

          this._tagLen = (options && options.tagLength) || blockLength;
          this.reset();
      },
      reset: function(){
          this._mac.update(one);
          if (this._ctr) {
              this._ctr.reset();
          }
      },
      updateAAD: function(header){
          this._mac.update(header);
          return this;
      },
      initCrypt: function(isEncrypt, nonce){
          var self = this;
          self._tag = self._mac.finalize();
          self._isEnc = isEncrypt;

          self._mac.update(zero);
          nonce = self._mac.finalize(nonce);

          ext.xor(self._tag, nonce);

          self._ctr = AES.createEncryptor(self._ctrKey, {
              iv: nonce,
              mode: C.mode.CTR,
              padding: C.pad.NoPadding
          });
          self._buf = new WordArray.init();

          self._mac.update(two);

          return self;
      },
      update: function(msg) {
          if (typeof msg === "string") {
              msg = C.enc.Utf8.parse(msg);
          }
          var self = this;
          var buffer = self._buf;
          var isEncrypt = self._isEnc;
          buffer.concat(msg);

          var useBytes = isEncrypt ? buffer.sigBytes : Math.max(buffer.sigBytes - self._tagLen, 0);

          var data = useBytes > 0 ? ext.shiftBytes(buffer, useBytes) : new WordArray.init(); // guaranteed to be pure plaintext or ciphertext (without a tag during decryption)
          var xoredData = self._ctr.process(data);

          self._mac.update(isEncrypt ? xoredData : data);

          return xoredData;
      },
      finalize: function(msg){
          var self = this;
          var xoredData = msg ? self.update(msg) : new WordArray.init();
          var mac = self._mac;
          var ctFin = self._ctr.finalize();

          if (self._isEnc) {
              var ctTag = mac.finalize(ctFin);

              ext.xor(self._tag, ctTag);
              self.reset();
              return xoredData.concat(ctFin).concat(self._tag);
          } else {
              // buffer must contain only the tag at this point
              var ctTag = mac.finalize();

              ext.xor(self._tag, ctTag);
              self.reset();
              if (ext.equals(self._tag, self._buf)) {
                  return xoredData.concat(ctFin);
              } else {
                  return false; // tag doesn't match
              }
          }
      },
      encrypt: function(plaintext, nonce, adArray){
          var self = this;
          if (adArray) {
              Array.prototype.forEach.call(adArray, function(ad){
                  self.updateAAD(ad);
              });
          }
          self.initCrypt(true, nonce);

          return self.finalize(plaintext);
      },
      decrypt: function(ciphertext, nonce, adArray){
          var self = this;
          if (adArray) {
              Array.prototype.forEach.call(adArray, function(ad){
                  self.updateAAD(ad);
              });
          }
          self.initCrypt(false, nonce);

          return self.finalize(ciphertext);
      }
  });


  /* JavaScript Implementation of Blowfish
   * Copyright (C) 2007 Nils Reimers (www.php-einfach.de)
   *
   * Blowfish was designed in 1993 by Bruce Schneier as a fast,
   * free alternative to existing encryption algorithms.
   *
   * It is a 64-bit Feistel cipher, consisting of 16 rounds.
   * Blowfish has a key length of anywhere from 32 bits up to 448 bits.
   *
   * Blowfish uses a large key-dependent S-boxes, a complex key shedule and a 18-entry P-Box
   *
   * Blowfish is unpatented and license-free, and is available free for all uses.
   *
   * ***********************
   * Diese Implementierung darf frei verwendet werden, der Author uebernimmt keine
   * Haftung fuer die Richtigkeit, Fehlerfreiheit oder die Funktionsfaehigkeit dieses Scripts.
   * Benutzung auf eigene Gefahr.
   *
   * Ueber einen Link auf www.php-einfach.de wuerden wir uns freuen.
   *
   * ************************
   * You can use this Blowfish-implementation without restriction including without limitation
   * the rights to use, modify and/or merge of this implementation.
   *
   * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
   * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
   * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
   * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE
   *
   *
   * ************************
   */

  // Shortcuts
  var C_lib = C.lib;
  var BlockCipher = C_lib.BlockCipher;
  var C_algo = C.algo;
  var rounds = 16;

  var pbox_def = [
      0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
      0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
      0x9216d5d9, 0x8979fb1b
  ];

  var sbox0_def = [
      0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
      0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
      0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
      0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
      0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
      0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
      0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
      0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
      0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
      0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
      0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
      0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
      0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
      0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
      0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
      0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
      0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3, 0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
      0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279, 0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
      0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
      0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db, 0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
      0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
      0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
      0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4, 0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
      0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
      0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
      0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299, 0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
      0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
      0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
      0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa, 0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
      0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
      0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
      0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664, 0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a
  ];

  var sbox1_def = [
      0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
      0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
      0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6, 0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
      0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e, 0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
      0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737, 0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
      0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff, 0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
      0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
      0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41, 0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
      0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
      0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
      0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c, 0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
      0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16, 0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
      0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
      0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
      0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
      0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
      0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
      0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802, 0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
      0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510, 0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
      0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
      0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50, 0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
      0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
      0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99, 0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
      0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
      0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
      0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105, 0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
      0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
      0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
      0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
      0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
      0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
      0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20, 0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7
  ];

  var sbox2_def = [
      0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
      0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af, 0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
      0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
      0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a, 0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
      0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee, 0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
      0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
      0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
      0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
      0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
      0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
      0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17, 0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
      0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
      0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
      0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0, 0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
      0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
      0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
      0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3, 0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
      0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
      0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350, 0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
      0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
      0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
      0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
      0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
      0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2, 0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
      0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e, 0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
      0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
      0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
      0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
      0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634, 0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
      0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
      0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
      0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837, 0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0
  ];

  var sbox3_def = [
      0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
      0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b, 0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
      0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
      0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304, 0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
      0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4, 0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
      0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
      0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
      0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28, 0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
      0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
      0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
      0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a, 0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
      0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
      0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
      0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680, 0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
      0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
      0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
      0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370, 0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
      0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
      0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8, 0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
      0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9, 0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
      0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
      0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
      0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1, 0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
      0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964, 0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
      0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
      0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f, 0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
      0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
      0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
      0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6, 0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
      0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
      0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
      0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f, 0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
  ];

  /**
   * AES block cipher algorithm.
   */
  var Blowfish = C_algo.Blowfish = BlockCipher.extend({
      _doReset: function () {
          // Shortcuts
          var key = this._key;
          var keySpread = key.clone();
          var keySize = key.sigBytes / 4;

          var keyAdds = Math.ceil((rounds+2) / keySize) - 1;

          var pbox = this._pbox = [],
              sbox0 = this._sbox0 = [],
              sbox1 = this._sbox1 = [],
              sbox2 = this._sbox2 = [],
              sbox3 = this._sbox3 = [];

          var i,
              v = [0, 0];

          for (i = 0; i < keyAdds; i++) {
              keySpread.concat(key);
          }

          for(i = 0; i < 256; i++) {
              sbox0[i] = sbox0_def[i];
              sbox1[i] = sbox1_def[i];
              sbox2[i] = sbox2_def[i];
              sbox3[i] = sbox3_def[i];
          }

          for(i = 0; i < rounds+2; i++)
              pbox[i] = pbox_def[i] ^ keySpread.words[i];

          for(i = 0; i < rounds+2; i += 2) {
              this.encryptBlock(v, 0);
              pbox[i] = v[0];
              pbox[i+1] = v[1];
          }

          for(i = 0; i < 256; i += 2) {
              this.encryptBlock(v, 0);
              sbox0[i] = v[0];
              sbox0[i+1] = v[1];
          }

          for(i = 0; i < 256; i += 2) {
              this.encryptBlock(v, 0);
              sbox1[i] = v[0];
              sbox1[i+1] = v[1];
          }

          for(i = 0; i < 256; i += 2) {
              this.encryptBlock(v, 0);
              sbox2[i] = v[0];
              sbox2[i+1] = v[1];
          }

          for(i = 0; i < 256; i += 2) {
              this.encryptBlock(v, 0);
              sbox3[i] = v[0];
              sbox3[i+1] = v[1];
          }
      },

      encryptBlock: function (M, offset) {
          var v_tmp,
              i,
              vl = M[offset],
              vr = M[offset + 1],
              self = this,
              pbox = self._pbox,
              sbox0 = self._sbox0,
              sbox1 = self._sbox1,
              sbox2 = self._sbox2,
              sbox3 = self._sbox3;

          for(i = 0; i < rounds; i++) {
              vl ^= pbox[i];
              vr ^= ((sbox0[(vl >>> 24) & 0xff] + sbox1[(vl >>> 16) & 0xff]) ^ sbox2[(vl >>> 8) & 0xff]) + sbox3[vl & 0xff];

              v_tmp = vl;
              vl = vr;
              vr = v_tmp;
          }

          v_tmp = vl;
          vl = vr;
          vr = v_tmp;

          vr ^= pbox[rounds];
          vl ^= pbox[rounds+1];

          M[offset] = vl;
          M[offset + 1] = vr;
      },

      decryptBlock: function (M, offset) {
          var v_tmp,
              i,
              vl = M[offset],
              vr = M[offset + 1],
              self = this,
              pbox = self._pbox,
              sbox0 = self._sbox0,
              sbox1 = self._sbox1,
              sbox2 = self._sbox2,
              sbox3 = self._sbox3;

          for(i = rounds+1; i > 1; i--) {
              vl ^= pbox[i];
              vr ^= ((sbox0[(vl >>> 24) & 0xff] + sbox1[(vl >>> 16) & 0xff]) ^ sbox2[(vl >>> 8) & 0xff]) + sbox3[vl & 0xff];

              v_tmp = vl;
              vl = vr;
              vr = v_tmp;
          }

          v_tmp = vl;
          vl = vr;
          vr = v_tmp;

          vr ^= pbox[1];
          vl ^= pbox[0];

          M[offset] = vl;
          M[offset + 1] = vr;
      },

      nRounds: 16,
      blockSize: 64/32
  });

  /**
   * Shortcut functions to the cipher's object interface.
   *
   * @example
   *
   *     var ciphertext = CryptoJS.Blowfish.encrypt(message, key, cfg);
   *     var plaintext  = CryptoJS.Blowfish.decrypt(ciphertext, key, cfg);
   */
  C.Blowfish = BlockCipher._createHelper(Blowfish);


}));