var fs = require("fs");

var aesContent = fs.readFileSync("../lib/cryptojs-aes.min.js", "utf8");
var neevaContent = fs.readFileSync("../src/neeva.js", "utf8");

var stats = { passed: 0, failed: 0 };

(function(){
	eval(aesContent);
	eval(neevaContent);

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

	var vectors = [
		{
			msg: "a",
			hash: "52ca54caad4617dcb051b2c4cc6c1c9e92753d1647a22405aa912c08"
		},
		{
			msg: "ab",
			hash: "0a163ca802692371b2d1a3035da3bb8f5e9b08ee82e2d5f41e532c1a"
		},
		{
			msg: "abc",
			hash: "b0c8be3dfcbc3886439256e1fe5682535d58c7dd9124dbc36cc37c91"
		},
	];

	vectors.forEach(function(vec, i){
		console.log("Message: '" + vec.msg + "'");
		var msgChunk, hash;
		var msgBytes = CryptoJS.enc.Utf8.parse(vec.msg);
		
		hash = CryptoJS.Neeva(msgBytes);
		assert(hash.toString(), vec.hash, "hash matches");
		
		// var neeva = CryptoJS.algo.Neeva.create();
		// var neevaf = CryptoJS.algo.Neeva.create();
		
		// for(var i = 0; i < (vec.msg.length/2-1); i++) {
			// msgChunk = CryptoJS.enc.Hex.parse(vec.msg.slice(i*2, i*2+2));
			// s256.update(msgChunk);
			// s512.update(msgChunk);
			// s256f.update(msgChunk);
			// s512f.update(msgChunk);
		// }
		
		// msgChunk = CryptoJS.enc.Hex.parse(vec.msg.slice(-2));
		// s256.update(msgChunk);
		// s512.update(msgChunk);
		// hash256 = s256f.finalize(msgChunk);
		// hash512 = s512f.finalize(msgChunk);
		
		// assert(hash256.toString(), vec.o256, "hash 256 matches (upd+fin)");
		// assert(hash512.toString(), vec.o512, "hash 512 matches (upd+fin)");
		
		// hash256 = s256.finalize();
		// hash512 = s512.finalize();
		
		// assert(hash256.toString(), vec.o256, "hash 256 matches (upd)");
		// assert(hash512.toString(), vec.o512, "hash 512 matches (upd)");
	});
})();

console.log("Neeva test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
	process.exit(1);
}