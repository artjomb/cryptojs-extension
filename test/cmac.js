var fs = require("fs");
var CryptoJS = require('crypto-js/core');
require('../build_node/cmac.js');

var stats = { passed: 0, failed: 0 };

var key = '2b7e151628aed2a6abf7158809cf4f3c';
var keyBytes = CryptoJS.enc.Hex.parse(key);

function test(message, expectedMAC){
    var cmacer = CryptoJS.algo.CMAC.create(keyBytes);
    var mac = cmacer.finalize(CryptoJS.enc.Hex.parse(message));
    var got = CryptoJS.enc.Hex.stringify(mac);
    var passed = got === expectedMAC;
    if (passed) {
        console.log("PASS msg: '" + message + "' mac: '" + expectedMAC + "' len: " + message.length);
        stats.passed++;
    } else {
        console.log("FAIL msg: '" + message + "' mac: '" + expectedMAC + "' got: '" + got + "' len: " + message.length);
        stats.failed++;
    }
}

function testOMAC2(key, message, expectedMAC){
    var keyBytes = CryptoJS.enc.Hex.parse(key);
    var cmacer = CryptoJS.algo.OMAC2.create(keyBytes);
    var mac = cmacer.finalize(CryptoJS.enc.Hex.parse(message));
    var got = CryptoJS.enc.Hex.stringify(mac);
    var passed = got === expectedMAC;
    if (passed) {
        console.log("PASS msg: '" + message + "' mac: '" + expectedMAC + "' len: " + message.length);
        stats.passed++;
    } else {
        console.log("FAIL msg: '" + message + "' mac: '" + expectedMAC + "' got: '" + got + "' len: " + message.length);
        stats.failed++;
    }
}

// Official test vectors (RFC 4493)
console.log("\nRFC 4493 test vectors");
test("", "bb1d6929e95937287fa37d129b756746");
test("6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c");
test("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827");
test("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe");


// test vectors from RFC 5297
console.log("\nRFC 5297 test vectors");
var key = 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0';
var keyBytes = CryptoJS.enc.Hex.parse(key);

test("00000000000000000000000000000000", "0e04dfafc1efbf040140582859bf073a");
test("101112131415161718191a1b1c1d1e1f2021222324252627", "f1f922b7f5193ce64ff80cb47d93f23b");
test("cac30894b8eaf254035bc20540357819", "85632d07c6e8f37f950acd320a2ecc93");

var key = '7f7e7d7c7b7a79787776757473727170';
var keyBytes = CryptoJS.enc.Hex.parse(key);

test("00000000000000000000000000000000", "c8b43b5974960e7ce6a5dd85231e591a");
test("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100", "3c9b689ab41102e4809547141dd0d15a");
test("102030405060708090a0", "d98c9b0be42cb2d7aa98478ed11eda1b");
test("09f911029d74e35bd84156c5635688c0", "128c62a1ce3747a8372c1c05a538b96d");
test("7468697320697320736f6d6520706c61696e7465787420746f20656e637279662d0c6201f3341575342a3745f5c625", "7bdb6e3b432667eb06f4d14bff2fbd0f");

// test vectors from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/omac/omac-ad.pdf
console.log("\nNIST test vectors");
// AES-192
var key = '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b';
var keyBytes = CryptoJS.enc.Hex.parse(key);

test("", "d17ddf46adaacde531cac483de7a9367");
test("6bc1bee22e409f96e93d7e117393172a", "9e99a7bf31e710900662f65e617c5184");
test("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "8a1de5be2eb31aad089a82e6ee908b0e");
test("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "a1d5df0eed790f794d77589659f39a11");

// AES-256
var key = '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4';
var keyBytes = CryptoJS.enc.Hex.parse(key);

test("", "028962f61b7bf89efc6b551f4667d983");
test("6bc1bee22e409f96e93d7e117393172a", "28a7023f452e8f82bd4bf28d8c37c35c");
test("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "aaf3d8f1de5640c232f5b169b9c911e6");
test("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "e1992190549f6ed5696a2c056c315410");

// sliding update test
console.log("\nSliding test");
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


// Shortcut function test
console.log("\nShortcut test");
var instantMAC = CryptoJS.CMAC(keyBytes, message).toString();
if (instantMAC === fullMAC) {
    console.log("PASS shortcut test MAC=" + instantMAC);
    stats.passed++;
} else {
    console.log("FAIL shortcut test full=" + fullMAC + " instant=" + instantMAC);
    stats.failed++;
}

console.log("CMAC test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
    process.exit(1);
}
