var fs = require("fs");

var aesContent = fs.readFileSync("../lib/cryptojs-aes.min.js", "utf8");
var binContent = fs.readFileSync("../build/enc-bin.js", "utf8");
var commonContent = fs.readFileSync("../build/common.js", "utf8");

var stats = { passed: 0, failed: 0 };

(function(){
    eval(aesContent);
    eval(binContent);
    eval(commonContent);
    
    var key = '1234567890123456';
    var keyBytes = CryptoJS.enc.Utf8.parse(key);
    var ivBytes = keyBytes.clone();
    
    function spaces(s){
        if (s || s.length) {
            return s.slice(0,4) + " " + spaces(s.slice(4));
        }
        return "";
    }
    
    function test(message, expected){
        if (typeof message !== "string") {
            message = CryptoJS.enc.Hex.stringify(message);
        }
        var passed = message === expected;
        if (passed) {
            console.log("PASS\n msg: '" + message + "' len: " + message.length);
            stats.passed++;
        } else {
            console.log("FAIL\n msg: '" + message + "' len: " + message.length + "\n expected: '" + spaces(expected) + "'");
            stats.failed++;
        }
    }
    
    console.log("\nSelf made test vectors for binary encoding");
    var binHexStr = [
        ["1010001101000101", "a345"],
        ["10100011010001101000110100010101", "a3468d15"],
        ["1010001101000110100011010001010111111111", "a3468d15ff"],
    ]
    binHexStr.forEach(function(entry){
        var binArray = CryptoJS.enc.Bin.parse(entry[0]);
        test(binArray.toString(), entry[1]);
        test(CryptoJS.enc.Bin.stringify(binArray), entry[0]);
    });
})();

console.log("Common test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
    process.exit(1);
}