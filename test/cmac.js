var fs = require("fs");

var aesContent = fs.readFileSync("../lib/cryptojs-aes.min.js", "utf8");
var cmacContent = fs.readFileSync("../build/cmac.js", "utf8");

var stats = { passed: 0, failed: 0 };

(function(){
    eval(aesContent);
    eval(cmacContent);
    
    var key = '2b7e151628aed2a6abf7158809cf4f3c';
    var keyBytes = CryptoJS.enc.Hex.parse(key);
    
    function test(message, expectedMAC){
        var cmacer = CryptoJS.algo.CMAC.create(keyBytes);
        var mac = cmacer.finalize(CryptoJS.enc.Hex.parse(message));
        var got = CryptoJS.enc.Hex.stringify(mac);
        var passed = got === expectedMAC;
        if (passed) {
            console.log("PASS msg=" + message + " mac=" + expectedMAC);
            stats.passed++;
        } else {
            console.log("FAIL msg=" + message + " mac=" + expectedMAC + " got=" + got);
            stats.failed++;
        }
    }
    
    // Official test vectors
    test("", "bb1d6929e95937287fa37d129b756746");
    test("6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c");
    test("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827");
    test("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe");
    
    // sliding update test
    var message = "This is some message that will be MAC'ed";
    var cmacer = CryptoJS.algo.CMAC.create(keyBytes);
    var fullMAC = cmacer.finalize(message).toString();
    
    var cmacProgressive = CryptoJS.algo.CMAC.create(keyBytes);
    for (var i = 0; i < message.length; i++) {
        cmacProgressive.update(message.slice(0, i));
        cmacProgressive.update(message.slice(i));
        var progressiveMAC = cmacProgressive.finalize().toString(); // auto-resets
        
        if (progressiveMAC === fullMAC) {
            console.log("PASS sliding test, i=" + i + " MAC=" + progressiveMAC);
            stats.passed++;
        } else {
            console.log("FAIL sliding test, i=" + i + " full=" + fullMAC + " prog=" + progressiveMAC);
            stats.failed++;
        }
    }
})();

console.log("CMAC test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
    process.exit(1);
}