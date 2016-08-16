;(function (root, factory) {
  if (typeof define === "function" && define.amd) {
    // AMD
    define(["crypto-js"], factory);
  }
  else {
    // Global (browser)
    factory(root.CryptoJS);
  }
}(this, function (C) {

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
  // Shortcuts
  var Base = C.lib.Base;
  var WordArray = C.lib.WordArray;
  var AES = C.algo.AES;
  var ext = C.ext;
  var OneZeroPadding = C.pad.OneZeroPadding;

  function aesBlock(key, data){
      var aes128 = AES.createEncryptor(key, { iv: WordArray.create(), padding: C.pad.NoPadding });
      var arr = aes128.finalize(data);
      return arr;
  }

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

          // Step 1
          var L = aesBlock(key, ext.const_Zero);

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
          this._K = key;

          this._const_Bsize = 16;

          this.reset();
      },

      reset: function () {
          this._x = ext.const_Zero.clone();
          this._counter = 0;
          this._buffer = WordArray.create();
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
              this._x = aesBlock(this._K, this._x);
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

          return aesBlock(this._K, M_last);
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


}));