var fs = require("fs");
var CryptoJS = require('crypto-js/core');
require('../build_node/spongent.js');

var stats = { passed: 0, failed: 0 };

function assert(got, expected, msg){
	var passed = got.toLowerCase() === expected.toLowerCase();
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
		ver: "88808",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "69971BF96DEF95BFC46822"
	},
	{
		ver: "8817688",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "4C02648B6C9B1E23748D08"
	},
	{
		ver: "1281288",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "6B7BA35EB09DE0F8DEF06AE555694C53"
	},
	{
		ver: "128256128",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "4E627FD888EEE0B76DBD3FACC90ACD06"
	},
	{
		ver: "16016016",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "13188A4917EA29E258362C047B9BF00C22B5FE91"
	},
	{
		ver: "16016080",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "B652C138CA1474DFC93504348E44766E01567033"
	},
	{
		ver: "160320160",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "0D7EA3168A2C3A2CDBB154E55C2131819DA44FB3"
	},
	{
		ver: "22422416",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "8443B12D2EEE4E09969A183205F5F7F684A711A5BE079A15F4CCDC30"
	},
	{
		ver: "224224112",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "DC192F029EC02D1BD9405A43C2B20D1FCBDE84DC3144E1FFAE978158"
	},
	{
		ver: "224448224",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "CCD6B76BB37026E9E6D3C46B71EF946B41D11271EADC3562DAB6BF9F"
	},
	{
		ver: "25625616",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "67DC8FC8B2EDBA6E55F4E68EC4F2B2196FE38DF9B1A760F4D43B4669160BF5A8"
	},
	{
		ver: "256256128",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "4E627FD888EEE0B76DBD3FACC90ACD065F19774FE6478CAB3A022A5A59280256"
	},
	{
		ver: "256512256",
		msg: "53706F6E6765202B2050726573656E74203D2053706F6E67656E74",
		hash: "CA79C19D73BB40F13AF89EC8E3853C6C9B70A995FEB97254F24C8A72B758ADC7"
	}
];

vectors.forEach(function(vec, i){
	console.log("Version: " + vec.ver + "  Message: '" + vec.msg + "'");
	var msgChunk, hash;
	var msgBytes;
	if (typeof vec.msg === "string")
		msgBytes = CryptoJS.enc.Hex.parse(vec.msg);
	else
		msgBytes = vec.msg;

	hash = CryptoJS["Spongent"+vec.ver](msgBytes);
	assert(hash.toString(), vec.hash, "hash matches");
});

console.log("Spongent test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
	process.exit(1);
}
