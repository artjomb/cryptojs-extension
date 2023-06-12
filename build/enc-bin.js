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


}));