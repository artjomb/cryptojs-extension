/* 
 * The MIT License (MIT)
 * 
 * Copyright (c) 2015 artjomb
 */
(function(C){
    // Shortcuts
    var Base = C.lib.Base;
    var WordArray = C.lib.WordArray;
    var AES = C.algo.AES;
    var ext = C.ext;
    var OneZeroPadding = C.pad.OneZeroPadding;
    var CMAC = C.algo.CMAC;
    var zero = WordArray.create([0x0, 0x0, 0x0, 0x0]);
    var one = WordArray.create([0x0, 0x0, 0x0, 0x1]);
    var two = WordArray.create([0x0, 0x0, 0x0, 0x2]);
    
    var EAX = C.EAX = Base.extend({
        init: function(/*key*/){
            // var len = key.sigBytes / 2;
            // this._tagKey = ext.shiftBytes(key, len);
            // this._tagKey = key.clone();
            // this._ctrKey = key;
        },
        encrypt: function(plaintext, key, nonce, options){
            this._tagKey = key.clone();
            this._ctrKey = key;
            
            var macer = CMAC.create(this._tagKey);
            macer.update(zero);
            nonce = macer.finalize(nonce);
            
            macer.update(one);
            var header = macer.finalize(options.header ? options.header : WordArray.create());
           
            var ciphertext = C.AES.encrypt(plaintext, this._ctrKey, {
                iv: nonce, 
                mode: C.mode.CTR, 
                padding: C.pad.NoPadding
            });
            
            macer.update(two);
            var ctTag = macer.finalize(ciphertext.ciphertext);
            
            ext.xor(ctTag, header);
            ext.xor(ctTag, nonce);
            
            return ciphertext.ciphertext.concat(ctTag);
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
})(CryptoJS);