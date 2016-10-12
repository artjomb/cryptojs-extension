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
var CMAC = C.algo.CMAC;
var zero = new WordArray.init([0x0, 0x0, 0x0, 0x0]);
var one = new WordArray.init([0x0, 0x0, 0x0, 0x1]);
var two = new WordArray.init([0x0, 0x0, 0x0, 0x2]);
var blockLength = 16;

var EAX = C.EAX = Base.extend({
    /**
     * Initializes the key of the cipher.
     *
     * @param {WordArray} key Key to be used for CMAC and CTR
     * @param {object} options Additonal options to tweak the encryption:
     *        splitKey - If true then the first half of the passed key will be
     *                   the CMAC key and the second half the CTR key
     *        tagLength - Length of the tag in bytes (for created tag and expected tag)
     */
    init: function(key, options){
        var macKey;
        if (options && options.splitKey) {
            var len = Math.floor(key.sigBytes / 2);
            macKey = ext.shiftBytes(key, len);
        } else {
            macKey = key.clone();
        }
        this._ctrKey = key;
        this._mac = CMAC.create(macKey);

        this._tagLen = (options && options.tagLength) || blockLength;
        this.reset();
    },
    reset: function(){
        this._mac.update(one);
        if (this._ctr) {
            this._ctr.reset();
        }
    },
    updateAAD: function(header){
        this._mac.update(header);
        return this;
    },
    initCrypt: function(isEncrypt, nonce){
        var self = this;
        self._tag = self._mac.finalize();
        self._isEnc = isEncrypt;

        self._mac.update(zero);
        nonce = self._mac.finalize(nonce);

        ext.xor(self._tag, nonce);

        self._ctr = AES.createEncryptor(self._ctrKey, {
            iv: nonce,
            mode: C.mode.CTR,
            padding: C.pad.NoPadding
        });
        self._buf = new WordArray.init();

        self._mac.update(two);

        return self;
    },
    update: function(msg) {
        if (typeof msg === "string") {
            msg = C.enc.Utf8.parse(msg);
        }
        var self = this;
        var buffer = self._buf;
        var isEncrypt = self._isEnc;
        buffer.concat(msg);

        var useBytes = isEncrypt ? buffer.sigBytes : Math.max(buffer.sigBytes - self._tagLen, 0);

        var data = useBytes > 0 ? ext.shiftBytes(buffer, useBytes) : new WordArray.init(); // guaranteed to be pure plaintext or ciphertext (without a tag during decryption)
        var xoredData = self._ctr.process(data);

        self._mac.update(isEncrypt ? xoredData : data);

        return xoredData;
    },
    finalize: function(msg){
        var self = this;
        var xoredData = msg ? self.update(msg) : new WordArray.init();
        var mac = self._mac;
        var ctFin = self._ctr.finalize();

        if (self._isEnc) {
            var ctTag = mac.finalize(ctFin);

            ext.xor(self._tag, ctTag);
            self.reset();
            return xoredData.concat(ctFin).concat(self._tag);
        } else {
            // buffer must contain only the tag at this point
            var ctTag = mac.finalize();

            ext.xor(self._tag, ctTag);
            self.reset();
            if (ext.equals(self._tag, self._buf)) {
                return xoredData.concat(ctFin);
            } else {
                return false; // tag doesn't match
            }
        }
    },
    encrypt: function(plaintext, nonce, adArray){
        var self = this;
        if (adArray) {
            Array.prototype.forEach.call(adArray, function(ad){
                self.updateAAD(ad);
            });
        }
        self.initCrypt(true, nonce);

        return self.finalize(plaintext);
    },
    decrypt: function(ciphertext, nonce, adArray){
        var self = this;
        if (adArray) {
            Array.prototype.forEach.call(adArray, function(ad){
                self.updateAAD(ad);
            });
        }
        self.initCrypt(false, nonce);

        return self.finalize(ciphertext);
    }
});
