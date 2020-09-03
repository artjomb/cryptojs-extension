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


}));