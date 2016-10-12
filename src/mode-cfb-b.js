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
