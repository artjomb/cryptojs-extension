// see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

/**
 * Cipher Feedback block mode.
 */
CryptoJS.mode.CFBb = (function () {
    var CFBb = CryptoJS.lib.BlockCipherMode.extend(),
        WordArray = CryptoJS.lib.WordArray, // shortcut
        bitshift = CryptoJS.ext.bitshift,
        neg = CryptoJS.ext.neg;

    CFBb.Encryptor = CFBb.extend({
        processBlock: function (words, offset) {
            console.log("processBlock: " + words.length + " words at " + offset);
            // Shortcuts
            var cipher = this._cipher;
            var blockSize = cipher.blockSize * 32; // in bits
            var iv = this._iv;
            var prev = this._prevBlock;
            var segmentSize = cipher.cfg.segmentSize; // in bits
            
            // TODO: this only works for segments smaller than 32 bits
            var fullSegmentMask = [
                ((1 << segmentSize) - 1) << (32 - segmentSize) // `s` most signiicant bits are set
            ];
            for(var i = 1; i < words.length; i++) {
                fullSegmentMask.push(0);
            }
            fullSegmentMask = WordArray.create(fullSegmentMask);
            var slidingSegmentMask = fullSegmentMask.clone(),
                slidingSegmentMaskShifted = slidingSegmentMask.clone(),
                slidingNegativeSegmentMask,
                prevCT;
            
            bitshift(slidingSegmentMaskShifted, -offset * 32);
            
            for(var i = 0; i < blockSize/segmentSize; i++) {
                console.log("  iteration: " + i + " of " + (blockSize/segmentSize));
                if (iv) {
                    prev = iv.slice(0); // clone

                    // Remove IV for subsequent blocks
                    iv = this._iv = undefined;
                } else {
                    // NOTE: This branch was tested and it works
                    prev = WordArray.create(prev);
                    bitshift(prev, segmentSize);
                    prev = prev.words;
                    prevCT = this._ct;
                    
                    // fill previous ciphertext up to the block size
                    while(prevCT.length < blockSize / 32) {
                        prevCT.push(0);
                    }
                    prevCT = WordArray.create(prevCT);
                    
                    // move to the back
                    bitshift(prevCT, -blockSize + segmentSize);
                    
                    // put together
                    for (var j = 0; j < prev.length; j++) {
                        prev[j] |= prevCT.words[j];
                    }
                }
                var currentPosition = offset * 32 + i * segmentSize;
                console.log("    prev:                      " + WordArray.create(prev).toString());
                console.log("    words begin:               " + WordArray.create(words).toString());
                var segKey = prev.slice(0); // clone
                cipher.encryptBlock(segKey, 0);

                // move segment in question to the front of the array
                var plaintextSlice = WordArray.create(words.slice(0));
                // console.log("    plaintextSlice before: " + plaintextSlice.toString());
                // TODO: there is something wrong with this shift:
                bitshift(plaintextSlice, currentPosition);
                console.log("    plaintextSlice shift:  " + currentPosition);
                // console.log("    plaintextSlice after:  " + plaintextSlice.toString());
                console.log("    plaintextSlice:            " + plaintextSlice.toString());
                
                // Encrypt segment
                for (var j = 0; j < Math.ceil(segmentSize / 32); j++) {
                    plaintextSlice.words[j] ^= segKey[j];
                }
                console.log("    plaintextSlice enc:        " + plaintextSlice.toString());
                // Filter only the current segment
                for (var j = 0; j < plaintextSlice.words.length; j++) {
                    plaintextSlice.words[j] &= fullSegmentMask.words[j];
                }
                console.log("    plaintextSlice mask:       " + plaintextSlice.toString());
                this._ct = plaintextSlice.words.slice(0, Math.ceil(segmentSize / 32));
                
                // remove the segment from the plaintext array
                console.log("      slidingSegmentMask pos:  " + slidingSegmentMask.toString());
                
                slidingNegativeSegmentMask = neg(slidingSegmentMaskShifted.clone());
                console.log("      slidingSegmentMask neg:  " + slidingNegativeSegmentMask.toString());
                for (var j = 0; j < words.length; j++) {
                    words[j] &= slidingNegativeSegmentMask.words[j];
                }
                
                // move filtered ciphertext segment to back to the correct place
                bitshift(plaintextSlice, -currentPosition);
                console.log("      plaintextSlice shifted:  " + plaintextSlice.toString());
                
                // add filtered ciphertext segment to the plaintext/ciphertext array
                for (var j = 0; j < words.length; j++) {
                    words[j] |= plaintextSlice.words[j];
                }
                
                // shift the segment mask further along
                bitshift(slidingSegmentMask, -segmentSize);
                bitshift(slidingSegmentMaskShifted, -segmentSize);
            }
            this._prevBlock = prev;
        }
    });

    CFBb.Decryptor = CFBb.extend({
        processBlock: function (words, offset) {
            // TODO: implement
        }
    });

    return CFBb;
}());
