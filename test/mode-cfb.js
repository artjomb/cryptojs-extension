var fs = require("fs");
var CryptoJS = require('crypto-js/core');
require('crypto-js/aes');
require('../build_node/enc-bin.js');
require('../build_node/mode-cfb-w.js');
require('../build_node/mode-cfb-b.js');

var stats = { passed: 0, failed: 0 };

var key = '1234567890123456';
var keyBytes = CryptoJS.enc.Utf8.parse(key);
var ivBytes = keyBytes.clone();
var pkcs7padding = CryptoJS.pad.Pkcs7;
var nopadding = {pad:function(){}, unpad:function(){}};
var padding = pkcs7padding;
var cfbw = CryptoJS.mode.CFBw;
var cfbb = CryptoJS.mode.CFBb;
var mode;

function spaces(s, spaced){
    spaced = spaced || 8;
    if (s || s.length) {
        return s.slice(0,spaced) + " " + spaces(s.slice(spaced));
    }
    return "";
}

function testEnc(message, expected, bitSize){
    var res = CryptoJS.AES.encrypt(message, keyBytes, {
        iv: ivBytes,
        mode: mode,
        padding: padding,
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

function testDec(ciphertext, expected, bitSize){
    var res = CryptoJS.AES.decrypt({ciphertext: ciphertext}, keyBytes, {
        iv: ivBytes,
        mode: mode,
        padding: padding,
        segmentSize: bitSize
    });
    var got = CryptoJS.enc.Hex.stringify(res);
    if (typeof expected !== "string") {
        expected = CryptoJS.enc.Hex.stringify(expected);
    }
    var passed = got === expected;
    if (passed) {
        console.log("PASS\n expected: '" + spaces(expected));
        stats.passed++;
    } else {
        console.log("FAIL\n expected: '" + spaces(expected) + "'\n      got: '" + spaces(got) + "'");
        stats.failed++;
    }
}

function testEncDec(message, bitSize){
    var enc = CryptoJS.AES.encrypt(message, keyBytes, {
        iv: ivBytes,
        mode: mode,
        padding: padding,
        segmentSize: bitSize
    });
    var res = CryptoJS.AES.decrypt(enc, keyBytes, {
        iv: ivBytes,
        mode: mode,
        padding: padding,
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
padding = nopadding;
mode = cfbb;
testEnc(text, "21a547bcdb6295b361d6fd0ac6bf82751f2052dd98a438c0", 8); // java no padding
testEnc(text, "2114c9ed57ad54a1ca10e18bde0dd0eb7841942594dfdf79", 16); // java no padding
// TODO fails:
// testEnc(text, "2114a47ffc231858190c5ebf2e44311ea5c6c70859cab865", 40); // java no padding
// testEnc(text, "2114a47ffc358f9a3e86835d265a2bfe75d6b7ae5669c04e", 48); // java no padding

padding = pkcs7padding;
mode = cfbw;
testEnc(text, "2114a47fa568ac16a4aff53cf5b090efe0824700f9d8a6fef838ac469ec9bcb3", 32); // java 2114a47fa568ac16a4aff53cf5b090efe0824700f9d8a6fe
testEnc(text, "2114a47ffc35e3ca16d0116af6d486769e56a540b942d3f27329f1af8db2bd66", 64); // java 2114a47ffc35e3ca16d0116af6d486769e56a540b942d3f2
testEnc(text, "2114a47ffc35e3caaf8b948218a96f747b792dbc478becfc6d43f9b92121b28a", 128); // java: 2114a47ffc35e3caaf8b948218a96f747b792dbc478becfc

console.log("\nenc/dec");
padding = nopadding;
[ cfbw, cfbb ].forEach(function(cfbMode){
    mode = cfbMode;
    testEncDec(text, 32);
    testEncDec(text, 64);
    // testEncDec(text, 96); // TODO fails
    testEncDec(text, 128);
});
// return;

// NIST
console.log("\nNIST test vectors");
var key128 = "2b7e151628aed2a6abf7158809cf4f3c";
var key192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
var key256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
var pt1 = "0110101111000001";
var pt8 = "6bc1bee22e409f96e93d7e117393172aae2d";
var pt128 = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
var iv = "000102030405060708090a0b0c0d0e0f";
var nistStrings = [
    {
        key: key128,
        iv: iv,
        pt: CryptoJS.enc.Bin.parse(pt1),
        ct: CryptoJS.enc.Bin.parse("0110100010110011"),
        segment: 1,
        padding: nopadding
    },
    {
        key: key192,
        iv: iv,
        pt: CryptoJS.enc.Bin.parse(pt1),
        ct: CryptoJS.enc.Bin.parse("1001001101011001"),
        segment: 1,
        padding: nopadding
    },
    {
        key: key256,
        iv: iv,
        pt: CryptoJS.enc.Bin.parse(pt1),
        ct: CryptoJS.enc.Bin.parse("1001000000101001"),
        segment: 1,
        padding: nopadding
    },
    {
        key: key128,
        iv: iv,
        pt: pt8,
        ct: "3b79424c9c0dd436bace9e0ed4586a4f32b9",
        segment: 8,
        padding: nopadding
    },
    {
        key: key192,
        iv: iv,
        pt: pt8,
        ct: "cda2521ef0a905ca44cd057cbf0d47a0678a",
        segment: 8,
        padding: nopadding
    },
    {
        key: key256,
        iv: iv,
        pt: pt8,
        ct: "dc1f1a8520a64db55fcc8ac554844e889700",
        segment: 8,
        padding: nopadding
    },
    {
        key: key128,
        iv: iv,
        pt: pt128,
        ct: "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6",
        segment: 128,
        padding: nopadding
    },
    {
        key: key192,
        iv: iv,
        pt: pt128,
        ct: "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff",
        segment: 128,
        padding: nopadding
    },
    {
        key: key256,
        iv: iv,
        pt: pt128,
        ct: "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471",
        segment: 128,
        padding: nopadding
    }
];

nistStrings.forEach(function(testCase){
    var modes = [cfbb];
    if (testCase.segment % 32 === 0) {
        modes.push(cfbw);
    }
    modes.forEach(function(cfbMode){
        padding = testCase.padding;
        mode = cfbMode;
        keyBytes = CryptoJS.enc.Hex.parse(testCase.key);
        ivBytes = CryptoJS.enc.Hex.parse(testCase.iv);

        var pt = testCase.pt.sigBytes ? testCase.pt : CryptoJS.enc.Hex.parse(testCase.pt);
        var ct = testCase.ct.sigBytes ? testCase.ct : CryptoJS.enc.Hex.parse(testCase.ct);
        testEnc(pt, ct, testCase.segment);
        testDec(ct, pt, testCase.segment);
    });
});

console.log("CFB[w/b] test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
    process.exit(1);
}
