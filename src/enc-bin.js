(function(C){
    C.enc.Bin = {
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var binChars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                
                for(var j = 7; j >= 0; j--) {
                    binChars.push((bite >>> j & 0x01).toString(2));
                }
            }

            return binChars.join('');
        },

        parse: function (binStr) {
            // TODO: implement
        }
    };
})(CryptoJS);