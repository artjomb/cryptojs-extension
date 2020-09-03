var fs = require("fs");
var CryptoJS = require('crypto-js/core');
require('crypto-js/sha1');
require('crypto-js/sha256');
require('../build_node/hkdf.js');

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
  console.log("\nRFC5869 HKDF Test Cases");
var tests = [
	{
		id: "TC1",
		ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		salt: "000102030405060708090a0b0c",
		info: "f0f1f2f3f4f5f6f7f8f9",
		L: 42,
		prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
		okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		hasher: CryptoJS.algo.SHA256
	},
	{
		id: "TC2",
		ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		L: 82,
		prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
		okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
		hasher: CryptoJS.algo.SHA256
	},
	{
		id: "TC3",
		ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		salt: "",
		info: "",
		L: 42,
		prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
		okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		hasher: CryptoJS.algo.SHA256
	},
	{
		id: "TC4",
		ikm: "0b0b0b0b0b0b0b0b0b0b0b",
		salt: "000102030405060708090a0b0c",
		info: "f0f1f2f3f4f5f6f7f8f9",
		L: 42,
		prk: "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
		okm: "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
		hasher: CryptoJS.algo.SHA1
	},
	{
		id: "TC5",
		ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		L: 82,
		prk: "8adae09a2a307059478d309b26c4115a224cfaf6",
		okm: "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
		hasher: CryptoJS.algo.SHA1
	},
	{
		id: "TC6",
		ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		salt: "",
		info: "",
		L: 42,
		prk: "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
		okm: "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
		hasher: CryptoJS.algo.SHA1
	},
	{
		id: "TC7",
		ikm: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
		info: "",
		L: 42,
		prk: "2adccada18779e7c2077ad2eb19d3f3e731385dd",
		okm: "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
		hasher: CryptoJS.algo.SHA1
	}
];

// add adjusted test cases where info is fully missing
tests.filter(function(t){
	return t.info === "";
}).forEach(function(t){
	var nt = JSON.parse(JSON.stringify(t));
	nt.id += " w/o info";
	nt.hasher = t.hasher;
	delete nt.info;
	tests.push(nt);
});

// run long tests
tests.forEach(function(t){
	var ikm = typeof t.ikm === "string" ? CryptoJS.enc.Hex.parse(t.ikm) : null;
	var salt = typeof t.salt === "string" ? CryptoJS.enc.Hex.parse(t.salt) : null;
	var info = typeof t.info === "string" ? CryptoJS.enc.Hex.parse(t.info) : null;

	var hkdf = CryptoJS.algo.HKDF.create(t.hasher, ikm, salt);
	assert(hkdf.extract().toString(), t.prk, "prk matches for " + t.id);
	assert(hkdf.expand(t.L, info).toString(), t.okm, "okm matches for " + t.id);
});

// filter long tests for test cases where short tests are applicable and run them
tests.filter(function(t){
	return (!t.info || t.info === "") && !t.salt;
}).forEach(function(t){
	var ikm = CryptoJS.enc.Hex.parse(t.ikm);
	var okm = CryptoJS.HKDF(t.hasher, ikm, t.L);
	assert(okm.toString(), t.okm, "okm matches for short " + t.id);
});

console.log("HKDF test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
    process.exit(1);
}
