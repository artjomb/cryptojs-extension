/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 artjomb
 */
var WordArray = C.lib.WordArray;
var crypto = window.crypto;
var TypedArray = Int32Array;
if (TypedArray && crypto && crypto.getRandomValues) {
    WordArray.random = function(nBytes){
        var array = new TypedArray(Math.ceil(nBytes / 4));
        crypto.getRandomValues(array);
        return new WordArray.init(
                [].map.call(array, function(word){
                    return word
                }),
                nBytes
        );
    };
} else {
    console.log("No cryptographically secure randomness source available");
}
