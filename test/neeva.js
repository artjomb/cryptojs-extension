var fs = require("fs");
var CryptoJS = require('crypto-js/core');
require('../build_node/neeva.js');

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

var vectors = [
	{
		msg: CryptoJS.lib.WordArray.create([0xa0000000], 0.5),
		hash: "52ca54caad4617dcb051b2c4cc6c1c9e92753d1647a22405aa912c08"
	},
	{
		msg: "ab",
		hash: "0a163ca802692371b2d1a3035da3bb8f5e9b08ee82e2d5f41e532c1a"
	},
	{
		msg: CryptoJS.lib.WordArray.create([0xabc00000], 1.5),
		hash: "b0c8be3dfcbc3886439256e1fe5682535d58c7dd9124dbc36cc37c91"
	},
];

vectors.forEach(function(vec, i){
	console.log("Message: '" + vec.msg + "'");
	var msgChunk, hash;
	var msgBytes;
	if (typeof vec.msg === "string")
		msgBytes = CryptoJS.enc.Hex.parse(vec.msg);
	else
		msgBytes = vec.msg;

	hash = CryptoJS.Neeva(msgBytes);
	assert(hash.toString(), vec.hash, "hash matches");
});

console.log("Neeva test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
	process.exit(1);
}
