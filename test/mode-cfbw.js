var fs = require("fs");

var aesContent = fs.readFileSync("../lib/cryptojs-aes.min.js", "utf8");
var cfbwContent = fs.readFileSync("../build/mode-cfbw.js", "utf8");
var cfbbContent = fs.readFileSync("../build/mode-cfb-b.js", "utf8");

var stats = { passed: 0, failed: 0 };

(function(){
    eval(aesContent);
    eval(cfbwContent);
    eval(cfbbContent);
    
    var key = '1234567890123456';
    var keyBytes = CryptoJS.enc.Utf8.parse(key);
    var ivBytes = keyBytes.clone();
    
    function spaces(s, spaced){
        spaced = spaced || 8
        if (s || s.length) {
            return s.slice(0,spaced) + " " + spaces(s.slice(spaced));
        }
        return "";
    }
    
    function testEnc(message, expected, bitSize){
        var res = CryptoJS.AES.encrypt(message, keyBytes, {
            iv: ivBytes,
            mode: CryptoJS.mode.CFBw,
            // padding: {pad:function(){}, unpad:function(){}},
            segmentSize: bitSize
        });
        var got = CryptoJS.enc.Hex.stringify(res.ciphertext);
        if (typeof expected !== "string") {
            expected = CryptoJS.enc.Hex.stringify(expected);
        }
        var passed = got === expected;
        if (passed) {
            console.log("PASS\n msg: '" + message + "' len: " + message.length + "\n expected: '" + spaces(expected));
            stats.passed++;
        } else {
            console.log("FAIL\n msg: '" + message + "' len: " + message.length + "\n expected: '" + spaces(expected) + "'\n      got: '" + spaces(got) + "'");
            stats.failed++;
        }
    }
    
    function testEncB(message, expected, bitSize){
        var res = CryptoJS.AES.encrypt(message, keyBytes, {
            iv: ivBytes,
            mode: CryptoJS.mode.CFBb,
            padding: {pad:function(){}, unpad:function(){}},
            segmentSize: bitSize
        });
        var got = CryptoJS.enc.Hex.stringify(res.ciphertext);
        if (typeof expected !== "string") {
            expected = CryptoJS.enc.Hex.stringify(expected);
        }
        var passed = got === expected;
        if (passed) {
            console.log("PASS\n msg: '" + message + "' len: " + message.length + "\n expected: '" + spaces(expected));
            stats.passed++;
        } else {
            console.log("FAIL\n msg: '" + message + "' len: " + message.length + "\n expected: '" + spaces(expected) + "'\n      got: '" + spaces(got) + "'");
            stats.failed++;
        }
    }
    
    function testEncDec(message, bitSize){
        var enc = CryptoJS.AES.encrypt(message, keyBytes, {
            iv: ivBytes,
            mode: CryptoJS.mode.CFBw,
            // padding: {pad:function(){}, unpad:function(){}},
            segmentSize: bitSize
        });
        var res = CryptoJS.AES.decrypt(enc, keyBytes, {
            iv: ivBytes,
            mode: CryptoJS.mode.CFBw,
            // padding: {pad:function(){}, unpad:function(){}},
            segmentSize: bitSize
        });
        var got = CryptoJS.enc.Utf8.stringify(res);
        var passed = got === message;
        if (passed) {
            console.log("PASS\n msg: '" + message + "' len: " + message.length);
            stats.passed++;
        } else {
            console.log("FAIL\n msg: '" + message + "' len: " + message.length + "\n      got: '" + got + "'");
            stats.failed++;
        }
    }
    
    console.log("\nSelf made test vectors");
    var text = "This is text tot encrypt";
    testEncB(text, "21a547bcdb6295b361d6fd0ac6bf82751f2052dd98a438c0", 8); // java no padding
    testEncB(text, "2114c9ed57ad54a1ca10e18bde0dd0eb7841942594dfdf79", 16); // java no padding
    // fails because of not implemented TODO:
    testEncB(text, "2114a47ffc231858190c5ebf2e44311ea5c6c70859cab865", 40); // java no padding
    testEnc(text, "2114a47fa568ac16a4aff53cf5b090efe0824700f9d8a6fef838ac469ec9bcb3", 32); // java 2114a47fa568ac16a4aff53cf5b090efe0824700f9d8a6fe
    testEnc(text, "2114a47ffc35e3ca16d0116af6d486769e56a540b942d3f27329f1af8db2bd66", 64); // java 2114a47ffc35e3ca16d0116af6d486769e56a540b942d3f2
    testEnc(text, "2114a47ffc35e3caaf8b948218a96f747b792dbc478becfc6d43f9b92121b28a", 128); // java: 2114a47ffc35e3caaf8b948218a96f747b792dbc478becfc
    
    console.log("\nenc/dec");
    testEncDec(text, 32);
    testEncDec(text, 64);
    testEncDec(text, 96); // fails because of padding
    testEncDec(text, 128);
    
    
    // NIST
    keyBytes = CryptoJS.enc.Hex.parse("7e151628aed2a6abf7158809cf4");
    ivBytes = CryptoJS.enc.Hex.parse("0102030405060708090a0b0c0d0");
    
    // var pt = CryptoJS.enc.Hex.parse("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    var pt = CryptoJS.enc.Hex.parse("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
    // var ct = CryptoJS.enc.Hex.parse("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6");
    var ct = CryptoJS.enc.Hex.parse("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b");
    
    // test(pt, ct, 128)
})();

console.log("CFB[w/b] test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
    process.exit(1);
}