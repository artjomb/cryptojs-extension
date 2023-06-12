var fs = require("fs");
var CryptoJS = require('crypto-js/core');
require('../build_node/gost-streebog.js');

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

function repeat(str, num)
{
	return new Array(num + 1).join(str);
}

var msg1 = "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130";
var msg2 = "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1";
var vectors = [
	{
		msg: msg1,
		o512: "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b",
		o256: "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d"
	},
	{
		msg: msg2,
		o512: "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e",
		o256: "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d"
	},
	{
		msg: "",
		o512: "8a1a1c4cbf909f8ecb81cd1b5c713abad26a4cac2a5fda3ce86e352855712f36a7f0be98eb6cf51553b507b73a87e97946aebc29859255049f86aa09a25d948e",
		o256: "bbe19c8d2025d99f943a932a0b365a822aa36a4c479d22cc02c8973e219a533f"
	},
	{
		msg: repeat(msg1, 10),
		o512: "e92553f0aa6bbe29db2c23b07343bb766615bd1e0b711b321b8f19ff58fa2291904709b18543aa51feb9987d8c87f766f7075e5af27f3efddf0f364efaa495fd",
		o256: "b63ca5932de795ba78cc6ed1d7bd9c1057bf292234b84ca7033ee8ed2136b139"
	},
	{
		msg: repeat(msg2, 200),
		o512: "304336d4a76aac2c6922034b59416cc7b29a30f1580a6b3ec9a7db4de69e6dc6b9c684528b20126657a9879177ce89ce0282a6a8340614936ef11af3593639b7",
		o256: "66b2a8c76f8866d73a285d4d7aae9d4f6b0038702acd0e1595a110c99ad59dd3"
	},
];

vectors.forEach(function(vec, i){
	console.log("Message: '" + vec.msg + "'");
	var msgChunk, hash512, hash256;
	var msgBytes = CryptoJS.enc.Hex.parse(vec.msg);

	hash256 = CryptoJS.Streebog256(msgBytes);
	assert(hash256.toString(), vec.o256, "hash 256 matches");

	hash512 = CryptoJS.Streebog512(msgBytes);
	assert(hash512.toString(), vec.o512, "hash 512 matches");

	var s256 = CryptoJS.algo.Streebog256.create();
	var s512 = CryptoJS.algo.Streebog512.create();

	var s256f = CryptoJS.algo.Streebog256.create();
	var s512f = CryptoJS.algo.Streebog512.create();

	for(var i = 0; i < (vec.msg.length/2-1); i++) {
		msgChunk = CryptoJS.enc.Hex.parse(vec.msg.slice(i*2, i*2+2));
		s256.update(msgChunk);
		s512.update(msgChunk);
		s256f.update(msgChunk);
		s512f.update(msgChunk);
	}

	msgChunk = CryptoJS.enc.Hex.parse(vec.msg.slice(-2));
	s256.update(msgChunk);
	s512.update(msgChunk);
	hash256 = s256f.finalize(msgChunk);
	hash512 = s512f.finalize(msgChunk);

	assert(hash256.toString(), vec.o256, "hash 256 matches (upd+fin)");
	assert(hash512.toString(), vec.o512, "hash 512 matches (upd+fin)");

	hash256 = s256.finalize();
	hash512 = s512.finalize();

	assert(hash256.toString(), vec.o256, "hash 256 matches (upd)");
	assert(hash512.toString(), vec.o512, "hash 512 matches (upd)");
});

console.log("Streebog test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
	process.exit(1);
}
