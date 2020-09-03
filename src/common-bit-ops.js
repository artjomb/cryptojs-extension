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
