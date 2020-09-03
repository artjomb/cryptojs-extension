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


}));