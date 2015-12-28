/* 
 * The MIT License (MIT)
 * 
 * Copyright (c) 2015 artjomb
 */
(function(C){
	// Shortcuts
	var C_lib = C.lib;
	var Base = C_lib.Base;
	var WordArray = C_lib.WordArray;
	var Hasher = C_lib.Hasher;
	
	var HKDF = C.algo.HKDF = Base.extend({
		/**
		 * Initializes a newly created HKDF
		 * 
		 * @param {Hasher} hasher A hashing function such as CryptoJS.algo.SHA1
		 * @param {WordArray | String} key The secret key
		 * @param {WordArray | String} salt Optional non-secret salt value
		 *
		 * @example
		 * 
		 *     var hkdf = CryptoJS.algo.HKDF.create(CryptoJS.algo.SHA1, key);
		 */
		init: function(hasher, key, salt){
			var self = this;
			
			self._hashLen = Hasher._createHelper(hasher)('').sigBytes;
			salt = salt || WordArray.create([], self._hashLen);
			
			self._hmacer = Hasher._createHmacHelper(hasher);
			self._prk = self._hmacer(key, salt);
		},

		extract: function () {
			return this._prk;
		},
		
		expand: function (outputLength, info) {
			var previousBlock = WordArray.create(),
				result = WordArray.create(),
				i,
				self = this,
				iterations = Math.ceil(outputLength / self._hashLen);
			info = info || WordArray.create();
			
			for(i = 1; i <= iterations; i++) {
				previousBlock = self._hmacer(previousBlock.concat(info).concat(WordArray.create([i<<24], 1)), self._prk);
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
})(CryptoJS);