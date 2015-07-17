/* 
 * The MIT License (MIT)
 * 
 * Copyright (c) 2015 artjomb
 */
(function(C){
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
    var AES = C.algo.AES;
    
    // Constants
    ext.const_Zero = WordArray.create([0x00000000, 0x00000000, 0x00000000, 0x00000000]);
    ext.const_One = WordArray.create([0x00000000, 0x00000000, 0x00000000, 0x00000001]);
    ext.const_Rb = WordArray.create([0x00000000, 0x00000000, 0x00000000, 0x00000087]);
    ext.const_nonMSB = WordArray.create([0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF]); // 1^64 || 0^1 || 1^31 || 0^1 || 1^31
    
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
            var padding = WordArray.create(paddingWords, nPaddingBytes);

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
        var left = ext.leftmostBytes(wordArray, n * 4);
        wordArray.words = wordArray.words.slice(n);
        wordArray.sigBytes -= n * 4;
        return left;
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
        
        var shiftedArray = WordArray.create();
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
        if (carry === 1) {
            ext.xor(wordArray, ext.const_Rb);
        }
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
        for(var i = 0; i < arr1.words.length; i++) {
            if (arr1.words[i] !== arr2.words[i]) {
                return false;
            }
        }
        return true;
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
})(CryptoJS);/**
 * Cipher Feedback block mode with segment size parameter according to
 * http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf. 
 * The segment size can be anything from 1 bit up to the block size of the 
 * underlying block cipher.
 * 
 * Current limitation: only segment sizes that divide the block size evenly 
 * are supported.
 */
CryptoJS.mode.CFBb = (function () {
    var CFBb = CryptoJS.lib.BlockCipherMode.extend(),
        WordArray = CryptoJS.lib.WordArray, // shortcut
        bitshift = CryptoJS.ext.bitshift,
        neg = CryptoJS.ext.neg;

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
        
        fullSegmentMask = WordArray.create(fullSegmentMask);
        
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
                
                prev = WordArray.create(prev);
                bitshift(prev, segmentSize);
                prev = prev.words;
                previousCiphertextSegment = self._ct;
                
                // fill previous ciphertext up to the block size
                while(previousCiphertextSegment.length < blockSize / 32) {
                    previousCiphertextSegment.push(0);
                }
                previousCiphertextSegment = WordArray.create(previousCiphertextSegment);
                
                // move to the back
                bitshift(previousCiphertextSegment, -blockSize + segmentSize);
                
                // put together
                for (var j = 0; j < prev.length; j++) {
                    prev[j] |= previousCiphertextSegment.words[j];
                }
            }

            currentPosition = offset * 32 + i * segmentSize;
            
            // move segment in question to the front of the array
            var plaintextSlice = WordArray.create(words.slice(0));
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
    
    return CFBb;
}());
