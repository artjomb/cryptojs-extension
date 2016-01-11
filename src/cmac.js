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
    
    var CMAC = C.algo.CMAC = Base.extend({
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
            ext.dbl(K1);
            
            // Step 3
            if (!this._isTwo) {
                var K2 = K1.clone();
                ext.dbl(K2);
            } else {
                var K2 = L.clone();
                ext.inv(K2);
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
            if (!messageUpdate) {
                return this;
            }
            
            // Shortcuts
            var buffer = this._buffer;
            var bsize = this._const_Bsize;
            
            if (typeof messageUpdate === "string") {
                messageUpdate = C.enc.Utf8.parse(messageUpdate);
            }
            
            buffer.concat(messageUpdate);
            
            while(buffer.sigBytes > bsize){
                var M_i = ext.shiftBytes(buffer, bsize);
                ext.xor(this._x, M_i);
                this._x.clamp();
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
        },
        
        _isTwo: false
    });
    
    /**
     * Directly invokes the CMAC and returns the calculated MAC.
     * 
     * @param {WordArray} key The key to be used for CMAC
     * @param {WordArray|string} message The data to be MAC'ed (either WordArray or UTF-8 encoded string)
     *
     * @returns {WordArray} MAC
     */
    C.CMAC = function(key, message){
        return CMAC.create(key).finalize(message);
    };
    
    C.algo.OMAC1 = CMAC;
    C.algo.OMAC2 = CMAC.extend({
        _isTwo: true
    });
})(CryptoJS);