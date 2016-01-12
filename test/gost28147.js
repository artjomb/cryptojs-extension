var fs = require("fs");

/* 
 * Testcases where randomly generated from BouncyCastle's Java implementation 
 * of GOST28147 in ECB mode without padding. The implementation was checked 
 * against https://github.com/sftp/gost28147
 */
var testcases = require("./gost28147-ecb.json");

var aesContent = fs.readFileSync("../lib/cryptojs-aes.min.js", "utf8");
var ecbContent = fs.readFileSync("../lib/cryptojs-mode-ecb.js", "utf8");
var b64Content = fs.readFileSync("../lib/cryptojs-enc-base64.js", "utf8");
var gostContent = fs.readFileSync("../src/gost28147.js", "utf8");

var stats = { passed: 0, failed: 0 };

(function(){
	eval(aesContent);
	eval(ecbContent);
	eval(b64Content);
	eval(gostContent);
	
	CryptoJS.pad.NoPadding = {
		pad: function () {},
		unpad: function () {}
	};

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
	
	function repeat(str, num)
	{
		return new Array(num + 1).join(str);
	}
	
	function b64b16(b64string) {
		return CryptoJS.enc.Base64.parse(b64string).toString();
	}

	testcases.forEach(function(tc, i){
		console.log("Testcase: " + i);
		var keyBytes = CryptoJS.enc.Base64.parse(tc.key);
		var ptBytes = CryptoJS.enc.Base64.parse(tc.pt);
		var ctBytes = CryptoJS.enc.Base64.parse(tc.ct);
		
		var ct = CryptoJS.Gost28147.encrypt(ptBytes, keyBytes, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding });
		// assert(ct.ciphertext.toString(CryptoJS.enc.Base64), tc.ct, "ct matches");
		assert(ct.ciphertext.toString(), b64b16(tc.ct), "ct matches");
		
		var pt = CryptoJS.Gost28147.decrypt({ciphertext: ctBytes}, keyBytes, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding });
		// assert(pt.toString(CryptoJS.enc.Base64), tc.pt, "pt matches");
		assert(pt.toString(), b64b16(tc.pt), "pt matches");
	});
})();

console.log("GOST28147 test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
	process.exit(1);
}