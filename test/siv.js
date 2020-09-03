var fs = require("fs");
var CryptoJS = require('crypto-js/core');
require('../build_node/siv.js');

var stats = { passed: 0, failed: 0 };

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


// Deterministic Authenticated Encryption Example
console.log("\nDeterministic Authenticated Encryption Example");
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


// Nonce-Based Authenticated Encryption Example
console.log("\nNonce-Based Authenticated Encryption Example");
var sivKey = "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f";
var ad1 = "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100";
var ad2 = "102030405060708090a0";
var nonce = "09f911029d74e35bd84156c5635688c0";
var plaintext = "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553";

var keyBytes = CryptoJS.enc.Hex.parse(sivKey);
var adBytes1 = CryptoJS.enc.Hex.parse(ad1);
var adBytes2 = CryptoJS.enc.Hex.parse(ad2);
var nonceBytes = CryptoJS.enc.Hex.parse(nonce);
var ptBytes = CryptoJS.enc.Hex.parse(plaintext);

var s2v = CryptoJS.algo.S2V.create(CryptoJS.enc.Hex.parse(sivKey.slice(0,32)));
assert(s2v._d.toString(), "c8b43b5974960e7ce6a5dd85231e591a", "zero");

s2v.updateAAD(adBytes1);
assert(s2v._d.toString(), "adf31e285d3d1e1d4ddefc1e5bec63e9", "xor 1");

s2v.updateAAD(adBytes2);
assert(s2v._d.toString(), "826aa75b5e568eed3125bfb266c61d4e", "xor 2");

s2v.updateAAD(nonceBytes);
assert(s2v._d.toString(), "16592c17729a5a725567636168b48376", "xor nonce");

s2v.update(ptBytes);
assert(s2v.finalize().toString(), "7bdb6e3b432667eb06f4d14bff2fbd0f", "s2v final");

console.log();

var siv = CryptoJS.SIV.create(keyBytes);
var ct = siv.encrypt([ adBytes1, adBytes2, nonceBytes ], ptBytes);
assert(ct.toString(), "7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d", "ciphertext final");

console.log("SIV test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
    process.exit(1);
}
