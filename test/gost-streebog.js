var fs = require("fs");

var aesContent = fs.readFileSync("../lib/cryptojs-aes.min.js", "utf8");
var gostContent = fs.readFileSync("../src/gost-streebog.js", "utf8");

var stats = { passed: 0, failed: 0 };

(function(){
	eval(aesContent);
	eval(gostContent);

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

	var vectors = [
		{
			msg: "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130",
			o512: "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b",
			o256: "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d"
		},
		{
			msg: "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1",
			o512: "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e",
			o256: "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d"
		},
		{
			msg: "",
			o512: "8a1a1c4cbf909f8ecb81cd1b5c713abad26a4cac2a5fda3ce86e352855712f36a7f0be98eb6cf51553b507b73a87e97946aebc29859255049f86aa09a25d948e",
			o256: "bbe19c8d2025d99f943a932a0b365a822aa36a4c479d22cc02c8973e219a533f"
		},
	];

	vectors.forEach(function(vec, i){
		console.log("Message: '" + vec.msg + "'");
		var msgBytes = CryptoJS.enc.Hex.parse(vec.msg);
		
		var hash = CryptoJS.Streebog256(msgBytes);
		assert(hash.toString(), vec.o256, "hash 256 matches");
		
		hash = CryptoJS.Streebog512(msgBytes);
		assert(hash.toString(), vec.o512, "hash 512 matches");
	});
})();

console.log("Streebog test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
	process.exit(1);
}