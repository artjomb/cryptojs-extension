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
var CMAC = C.algo.CMAC;

/**
 * updateAAD must be used before update, because the additional data is
 * expected to be authenticated before the plaintext stream starts.
 */
var S2V = C.algo.S2V = Base.extend({
    init: function(key){
        this._blockSize = 16;
        this._cmacAD = CMAC.create(key);
        this._cmacPT = CMAC.create(key);
        this.reset();
    },
    reset: function(){
        this._buffer = new WordArray.init();
        this._cmacAD.reset();
        this._cmacPT.reset();
        this._d = this._cmacAD.finalize(ext.const_Zero);
        this._empty = true;
        this._ptStarted = false;
    },
    updateAAD: function(msgUpdate){
        if (this._ptStarted) {
            // It's not possible to authenticate any more additional data when the plaintext stream starts
            return this;
        }

        if (!msgUpdate) {
            return this;
        }

        if (typeof msgUpdate === "string") {
            msgUpdate = C.enc.Utf8.parse(msgUpdate);
        }

        this._d = ext.xor(ext.dbl(this._d), this._cmacAD.finalize(msgUpdate));
        this._empty = false;

        // Chainable
        return this;
    },
    update: function(msgUpdate){
        if (!msgUpdate) {
            return this;
        }

        this._ptStarted = true;
        var buffer = this._buffer;
        var bsize = this._blockSize;
        var wsize = bsize / 4;
        var cmac = this._cmacPT;
        if (typeof msgUpdate === "string") {
            msgUpdate = C.enc.Utf8.parse(msgUpdate);
        }

        buffer.concat(msgUpdate);

        while(buffer.sigBytes >= 2 * bsize){
            this._empty = false;
            var s_i = ext.popWords(buffer, wsize);
            cmac.update(s_i);
        }

        // Chainable
        return this;
    },
    finalize: function(msgUpdate){
        this.update(msgUpdate);

        var bsize = this._blockSize;
        var s_n = this._buffer;

        if (this._empty && s_n.sigBytes === 0) {
            return this._cmacAD.finalize(ext.const_One);
        }

        var t;
        if (s_n.sigBytes >= bsize) {
            t = ext.xorendBytes(s_n, this._d);
        } else {
            OneZeroPadding.pad(s_n, bsize);
            t = ext.xor(ext.dbl(this._d), s_n);
        }

        return this._cmacPT.finalize(t);
    }
});

var SIV = C.SIV = Base.extend({
    init: function(key){
        var len = key.sigBytes / 2;
        this._s2vKey = ext.shiftBytes(key, len);
        this._ctrKey = key;
    },
    encrypt: function(adArray, plaintext){
        if (!plaintext && adArray) {
            plaintext = adArray;
            adArray = [];
        }

        var s2v = S2V.create(this._s2vKey);
        Array.prototype.forEach.call(adArray, function(ad){
            s2v.updateAAD(ad);
        });
        var tag = s2v.finalize(plaintext);
        var filteredTag = ext.bitand(tag, ext.const_nonMSB);

        var ciphertext = C.AES.encrypt(plaintext, this._ctrKey, {
            iv: filteredTag,
            mode: C.mode.CTR,
            padding: C.pad.NoPadding
        });

        return tag.concat(ciphertext.ciphertext);
    },
    decrypt: function(adArray, ciphertext){
        if (!ciphertext && adArray) {
            ciphertext = adArray;
            adArray = [];
        }

        var tag = ext.shiftBytes(ciphertext, 16);
        var filteredTag = ext.bitand(tag, ext.const_nonMSB);

        var plaintext = C.AES.decrypt({ciphertext:ciphertext}, this._ctrKey, {
            iv: filteredTag,
            mode: C.mode.CTR,
            padding: C.pad.NoPadding
        });

        var s2v = S2V.create(this._s2vKey);
        Array.prototype.forEach.call(adArray, function(ad){
            s2v.updateAAD(ad);
        });
        var recoveredTag = s2v.finalize(plaintext);

        if (ext.equals(tag, recoveredTag)) {
            return plaintext;
        } else {
            return false;
        }
    }
});
