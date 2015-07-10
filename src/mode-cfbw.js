// see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

/**
 * Cipher Feedback block mode.
 */
CryptoJS.mode.CFBx = (function () {
    var CFBx = CryptoJS.lib.BlockCipherMode.extend();

    CFBx.Encryptor = CFBx.extend({
        processBlock: function (words, offset) {
            // Shortcuts
            var cipher = this._cipher;
            var blockSize = cipher.blockSize; // in words
            var iv = this._iv;
            var prev = this._prevBlock;
            var segmentSize = cipher.cfg.segmentSize / 32; // in words
            
            // somehow the wrong indexes are used
            for(var i = 0; i < blockSize/segmentSize; i++) {
                if (iv) {
                    prev = iv.slice(0); // clone

                    // Remove IV for subsequent blocks
                    iv = this._iv = undefined;
                } else {
                    prev = prev.slice(segmentSize).concat(this._ct);
                }
                var segKey = prev.slice(0); // clone
                cipher.encryptBlock(segKey, 0);

                // Encrypt segment
                for (var j = 0; j < segmentSize; j++) {
                    words[offset + i * segmentSize + j] ^= segKey[j];
                }
                this._ct = words.slice(offset + i * segmentSize, offset + i * segmentSize + segmentSize);
            }
            this._prevBlock = prev;
        }
    });

    CFBx.Decryptor = CFBx.extend({
        processBlock: function (words, offset) {
            // Shortcuts
            var cipher = this._cipher;
            var blockSize = cipher.blockSize; // in words
            var iv = this._iv;
            var prev = this._prevBlock;
            var segmentSize = cipher.cfg.segmentSize / 32; // in words
            
            // somehow the wrong indexes are used
            for(var i = 0; i < blockSize/segmentSize; i++) {
                if (iv) {
                    prev = iv.slice(0); // clone

                    // Remove IV for subsequent blocks
                    iv = this._iv = undefined;
                } else {
                    prev = prev.slice(segmentSize).concat(this._ct);
                }
                this._ct = words.slice(offset + i * segmentSize, offset + i * segmentSize + segmentSize);
                var segKey = prev.slice(0); // clone
                cipher.encryptBlock(segKey, 0);

                // Encrypt segment
                for (var j = 0; j < segmentSize; j++) {
                    words[offset + i * segmentSize + j] ^= segKey[j];
                }
            }
            this._prevBlock = prev;
        }
    });

    return CFBx;
}());
