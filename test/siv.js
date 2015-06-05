var fs = require("fs");

var aesContent = fs.readFileSync("../lib/cryptojs-aes.min.js", "utf8");
var ctrContent = fs.readFileSync("../lib/cryptojs-mode-ctr-min.js", "utf8");
var sivContent = fs.readFileSync("../build/siv.js", "utf8");

var stats = { passed: 0, failed: 0 };

(function(){
    eval(aesContent);
    eval(ctrContent);
    eval(sivContent);
    
    function assert(got, expected, msg){
        var passed = got === expected;
        if (msg) {
            msg = " (" + msg + ")";
        } else {
            msg = "";
        }
        if (passed) {
            console.log("PASS got=" + got + msg);
            stats.passed++;
        } else {
            console.log("FAIL got=" + got + " expected=" + expected + msg);
            stats.failed++;
        }
    }
    
    var sivKey1 = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0";
    var sivKey2 = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    var ad = "101112131415161718191a1b1c1d1e1f2021222324252627";
    var plaintext = "112233445566778899aabbccddee";

    var keyBytes1 = CryptoJS.enc.Hex.parse(sivKey1);
    var keyBytes2 = CryptoJS.enc.Hex.parse(sivKey2);
    var adBytes = CryptoJS.enc.Hex.parse(ad);
    var ptBytes = CryptoJS.enc.Hex.parse(plaintext);

    var s2v = CryptoJS.algo.S2V.create(keyBytes1);
    assert(s2v._d.toString(), "0e04dfafc1efbf040140582859bf073a", "zero");

    s2v.updateAAD(adBytes);
    assert(s2v._d.toString(), "edf09de876c642ee4d78bce4ceedfc4f", "xor");

    s2v.update(ptBytes);
    assert(s2v.finalize().toString(), "85632d07c6e8f37f950acd320a2ecc93", "s2v final");

    var siv = CryptoJS.SIV.create(keyBytes1.clone().concat(keyBytes2));
    var ct = siv.encrypt([ adBytes ], ptBytes);
    assert(ct.toString(), "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c", "ciphertext final");

    var recoveredPT = siv.decrypt([ adBytes ], ct);
    assert(recoveredPT.toString(), plaintext, "recovered plaintext");
})();

console.log("CMAC test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
    process.exit(1);
}