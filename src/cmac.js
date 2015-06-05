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
    
    function aesBlock(key, data){
        var aes128 = AES.createEncryptor(key, { iv: WordArray.create(), padding: C.pad.NoPadding });
        var arr = aes128.finalize(data);
        return arr;
    }
    
    C.algo.CMAC = Base.extend({
        /**
         * Initializes a newly created CMAC
         * 
         * @param {WordArray} key The secret key
         *
         * @example
         * 
         *     var cmacer = CryptoJS.algo.CMAC.create(key);
         */
        init: function(key){
            // generate sub keys...
            
            // Step 1
            var L = aesBlock(key, ext.const_Zero);
            
            // Step 2
            var K1 = L.clone();
            ext.bitshift(K1, 1);
            if (ext.msb(L) === 1) {
                ext.xor(K1, ext.const_Rb);
            }
            
            // Step 3
            var K2 = K1.clone();
            ext.bitshift(K2, 1);
            if (ext.msb(K2) === 1) {
                ext.xor(K2, ext.const_Rb);
            }
            
            this._K1 = K1;
            this._K2 = K2;
            this._K = key;
            
            this._const_Bsize = 16;
            
            this.reset();
        },
        
        reset: function () {
            this._x = ext.const_Zero.clone();
            this._counter = 0;
            this._buffer = WordArray.create();
        },

        update: function (messageUpdate) {
            // Shortcuts
            var buffer = this._buffer;
            var bsize = this._const_Bsize;
            
            if (typeof messageUpdate === "string") {
                messageUpdate = C.enc.Utf8.parse(messageUpdate);
            }
            
            buffer.concat(messageUpdate);
            
            while(buffer.sigBytes > bsize){
                var M_i = ext.shift(buffer, bsize);
                ext.xor(this._x, M_i);
                this._x = aesBlock(this._K, this._x);
                this._counter++;
            }

            // Chainable
            return this;
        },
        
        finalize: function (messageUpdate) {
            this.update(messageUpdate);
            
            // Shortcuts
            var buffer = this._buffer;
            var bsize = this._const_Bsize;
            
            var M_last = buffer.clone();
            if (buffer.sigBytes === bsize) {
                ext.xor(M_last, this._K1);
            } else {
                OneZeroPadding.pad(M_last, bsize/4);
                ext.xor(M_last, this._K2);
            }
            
            ext.xor(M_last, this._x);

            this.reset(); // Can be used immediately afterwards
            
            return aesBlock(this._K, M_last);
        }
    });
})(CryptoJS);