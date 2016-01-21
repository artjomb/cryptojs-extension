var fs = require("fs");

var aesContent = fs.readFileSync("../lib/cryptojs-aes.min.js", "utf8");
var ecbContent = fs.readFileSync("../lib/cryptojs-mode-ecb.js", "utf8");
var teaContent = fs.readFileSync("../src/tea.js", "utf8");

var stats = { passed: 0, failed: 0 };

(function(){
	eval(aesContent);
	eval(ecbContent);
	eval(teaContent);
	
	var testcases = [
		{ key: "00000000000000000000000000000000", pt: "0000000000000000", ct:"41EA3A0A94BAA940"},
		{ key: "0000000094BAA94041EA3A0A00000000", pt: "41EA3A0A94BAA940", ct:"2030830DAA7D6D45"},
		{ key: "AA7D6D4594BAA94041EA3A0A2030830D", pt: "2030830DAA7D6D45", ct:"B58092E8CB06B5A5"},
		{ key: "AA7D6D455FBC1CE5F46AA8E22030830D", pt: "B58092E8CB06B5A5", ct:"B7AA21BADE4392A0"},
		{ key: "743EFFE55FBC1CE5F46AA8E2979AA2B7", pt: "B7AA21BADE4392A0", ct:"D9E28852535C1E30"},
		{ key: "743EFFE50CE002D52D8820B0979AA2B7", pt: "D9E28852535C1E30", ct:"BB8AF974E4ACD957"},
		{ key: "909226B20CE002D52D8820B02C105BC3", pt: "BB8AF974E4ACD957", ct:"0D099DA417937882"},
		{ key: "909226B21B737A572081BD142C105BC3", pt: "0D099DA417937882", ct:"5487B6E871EB4D0D"},
		{ key: "E1796BBF1B737A572081BD147897ED2B", pt: "5487B6E871EB4D0D", ct:"830A392A0E9B4803"},
		{ key: "E1796BBF15E83254A38B843E7897ED2B", pt: "830A392A0E9B4803", ct:"3A129BD454CDCEF3"},
		{ key: "B5B4A54C15E83254A38B843E428576FF", pt: "3A129BD454CDCEF3", ct:"781432E94DA8CE3D"},
		{ key: "B5B4A54C5840FC69DB9FB6D7428576FF", pt: "781432E94DA8CE3D", ct:"D7C1AF0306797E67"},
		{ key: "B3CDDB2B5840FC69DB9FB6D79544D9FC", pt: "D7C1AF0306797E67", ct:"42E9DD867F69466D"},
		{ key: "B3CDDB2B2729BA0499766B519544D9FC", pt: "42E9DD867F69466D", ct:"62AEE01FBD5AC206"},
		{ key: "0E97192D2729BA0499766B51F7EA39E3", pt: "62AEE01FBD5AC206", ct:"8E65E82A08F68B22"},
		{ key: "0E97192D2FDF31261713837BF7EA39E3", pt: "8E65E82A08F68B22", ct:"F4774C36874D8E6E"},
		{ key: "89DA97432FDF31261713837B039D75D5", pt: "F4774C36874D8E6E", ct:"CC768118AEA06739"},
		{ key: "89DA9743817F561FDB650263039D75D5", pt: "CC768118AEA06739", ct:"BBC88F18B395A46D"},
		{ key: "3A4F332E817F561FDB650263B855FACD", pt: "BBC88F18B395A46D", ct:"7AC046217844A2AD"},
		{ key: "3A4F332EF93BF4B2A1A54442B855FACD", pt: "7AC046217844A2AD", ct:"656535F85EC8A072"},
		{ key: "6487935CF93BF4B2A1A54442DD30CF35", pt: "656535F85EC8A072", ct:"C21E07C890DE0BA5"},
		{ key: "6487935C69E5FF1763BB438ADD30CF35", pt: "C21E07C890DE0BA5", ct:"2E1958972B5E8209"},
		{ key: "4FD9115569E5FF1763BB438AF32997A2", pt: "2E1958972B5E8209", ct:"0B113B2F1ADF9C80"},
		{ key: "4FD91155733A639768AA78A5F32997A2", pt: "0B113B2F1ADF9C80", ct:"E0006CA3985DF678"},
		{ key: "D784E72D733A639768AA78A51329FB01", pt: "E0006CA3985DF678", ct:"02345F5572AE441E"},
		{ key: "D784E72D019427896A9E27F01329FB01", pt: "02345F5572AE441E", ct:"4FEC7D6C3A6A4BCB"},
		{ key: "EDEEACE6019427896A9E27F05CC5866D", pt: "4FEC7D6C3A6A4BCB", ct:"A17A8F88083B108A"},
		{ key: "EDEEACE609AF3703CBE4A8785CC5866D", pt: "A17A8F88083B108A", ct:"2C331276A5E02D0B"},
		{ key: "480E81ED09AF3703CBE4A87870F6941B", pt: "2C331276A5E02D0B", ct:"C5CB8D58D7A42140"},
		{ key: "480E81EDDE0B16430E2F252070F6941B", pt: "C5CB8D58D7A42140", ct:"5991EFDEE9B5B20D"},
		{ key: "A1BB33E0DE0B16430E2F252029677BC5", pt: "5991EFDEE9B5B20D", ct:"59A8C4A13A5139EA"},
		{ key: "A1BB33E0E45A2FA95787E18129677BC5", pt: "59A8C4A13A5139EA", ct:"41A00B3F1D397C9F"},
		{ key: "BC824F7FE45A2FA95787E18168C770FA", pt: "41A00B3F1D397C9F", ct:"6ECE9A156671902E"},
		{ key: "BC824F7F822BBF8739497B9468C770FA", pt: "6ECE9A156671902E", ct:"03B9D491DD0AED1F"},
		{ key: "6188A260822BBF8739497B946B7EA46B", pt: "03B9D491DD0AED1F", ct:"8E92339332DA8723"},
		{ key: "6188A260B0F138A4B7DB48076B7EA46B", pt: "8E92339332DA8723", ct:"B79079C98E2A231F"},
		{ key: "EFA2817FB0F138A4B7DB4807DCEEDDA2", pt: "B79079C98E2A231F", ct:"60F296FF70E7A99E"},
		{ key: "EFA2817FC016913AD729DEF8DCEEDDA2", pt: "60F296FF70E7A99E", ct:"3D32E45FA2258E03"},
		{ key: "4D870F7CC016913AD729DEF8E1DC39FD", pt: "3D32E45FA2258E03", ct:"18BF449CEDFDBE1E"},
		{ key: "4D870F7C2DEB2F24CF969A64E1DC39FD", pt: "18BF449CEDFDBE1E", ct:"F728D28AD6107609"},
		{ key: "9B9779752DEB2F24CF969A6416F4EB77", pt: "F728D28AD6107609", ct:"4B1975CA66C24E2F"},
		{ key: "9B9779754B29610B848FEFAE16F4EB77", pt: "4B1975CA66C24E2F", ct:"0E0BE20BC4BA79FA"},
		{ key: "5F2D008F4B29610B848FEFAE18FF097C", pt: "0E0BE20BC4BA79FA", ct:"36C569EC96C10A2E"},
		{ key: "5F2D008FDDE86B25B24A864218FF097C", pt: "36C569EC96C10A2E", ct:"B10C073257989F5C"},
		{ key: "08B59FD3DDE86B25B24A8642A9F30E4E", pt: "B10C073257989F5C", ct:"C85337EC38F786C0"},
		{ key: "08B59FD3E51FEDE57A19B1AEA9F30E4E", pt: "C85337EC38F786C0", ct:"623FCE34069C83F6"},
		{ key: "0E291C25E51FEDE57A19B1AECBCCC07A", pt: "623FCE34069C83F6", ct:"631043911F59484D"},
		{ key: "0E291C25FA46A5A81909F23FCBCCC07A", pt: "631043911F59484D", ct:"AF1081C9302FEB15"},
		{ key: "3E06F730FA46A5A81909F23F64DC41B3", pt: "AF1081C9302FEB15", ct:"75C4BB5406097771"},
		{ key: "3E06F730FC4FD2D96CCD496B64DC41B3", pt: "75C4BB5406097771", ct:"0E5207C3A6F539A2"},
		{ key: "98F3CE92FC4FD2D96CCD496B6A8E4670", pt: "0E5207C3A6F539A2", ct:"2CD008AF24E175C7"},
		{ key: "98F3CE92D8AEA71E401D41C46A8E4670", pt: "2CD008AF24E175C7", ct:"D469048B8C5007C6"},
		{ key: "14A3C954D8AEA71E401D41C4BEE742FB", pt: "D469048B8C5007C6", ct:"FCD76F8E34D22871"},
		{ key: "14A3C954EC7C8F6FBCCA2E4ABEE742FB", pt: "FCD76F8E34D22871", ct:"41F85A6CD42951DB"},
		{ key: "C08A988FEC7C8F6FBCCA2E4AFF1F1897", pt: "41F85A6CD42951DB", ct:"DF75E6EE9CC492A5"},
		{ key: "C08A988F70B81DCA63BFC8A4FF1F1897", pt: "DF75E6EE9CC492A5", ct:"A27F6ACEA7955433"},
		{ key: "671FCCBC70B81DCA63BFC8A45D607259", pt: "A27F6ACEA7955433", ct:"E1454CF83476DB92"},
		{ key: "671FCCBC44CEC65882FA845C5D607259", pt: "E1454CF83476DB92", ct:"2EDE238C870AA382"},
		{ key: "E0156F3E44CEC65882FA845C73BE51D5", pt: "2EDE238C870AA382", ct:"F54246958C00C3BF"},
		{ key: "E0156F3EC8CE05E777B8C2C973BE51D5", pt: "F54246958C00C3BF", ct:"0670F8679BC8FAE2"},
		{ key: "7BDD95DCC8CE05E777B8C2C975CEA9B2", pt: "0670F8679BC8FAE2", ct:"B5FC91E4122DE829"},
		{ key: "7BDD95DCDAE3EDCEC244532D75CEA9B2", pt: "B5FC91E4122DE829", ct:"C981A368D7F04E41"},
		{ key: "AC2DDB9DDAE3EDCEC244532DBC4F0ADA", pt: "C981A368D7F04E41", ct:"9CA11ECB344F54B0"},
		{ key: "AC2DDB9DEEACB97E5EE54DE6BC4F0ADA", pt: "9CA11ECB344F54B0", ct:"815BA6C034D015DD"},
		{ key: "98FDCE40EEACB97E5EE54DE63D14AC1A", pt: "815BA6C034D015DD", ct:"58A343381C05429D"},
		{ key: "98FDCE40F2A9FBE306460EDE3D14AC1A", pt: "58A343381C05429D", ct:"8F58E0186CBD680C"},
		{ key: "F440A64CF2A9FBE306460EDEB24C4C02", pt: "8F58E0186CBD680C", ct:"B551A27DEEAE4156"},
		{ key: "F440A64C1C07BAB5B317ACA3B24C4C02", pt: "B551A27DEEAE4156", ct:"D15768AD4E0F7B4F"},
		{ key: "BA4FDD031C07BAB5B317ACA3631B24AF", pt: "D15768AD4E0F7B4F", ct:"CEE747EA6B002FDC"},
		{ key: "BA4FDD03770795697DF0EB49631B24AF", pt: "CEE747EA6B002FDC", ct:"3AC4C4F82D8266BA"},
		{ key: "97CDBBB9770795697DF0EB4959DFE057", pt: "3AC4C4F82D8266BA", ct:"303CD14516368E55"},
		{ key: "97CDBBB961311B3C4DCC3A0C59DFE057", pt: "303CD14516368E55", ct:"554443FDC5B07DBA"},
		{ key: "527DC60361311B3C4DCC3A0C0C9BA3AA", pt: "554443FDC5B07DBA", ct:"7D4EEFAA76BB47A4"},
		{ key: "527DC603178A5C983082D5A60C9BA3AA", pt: "7D4EEFAA76BB47A4", ct:"C015402881BE0844"},
		{ key: "D3C3CE47178A5C983082D5A6CC8EE382", pt: "C015402881BE0844", ct:"E8E1388613E3FE4E"},
		{ key: "D3C3CE470469A2D6D863ED20CC8EE382", pt: "E8E1388613E3FE4E", ct:"FCFACE18E85F91FB"},
		{ key: "3B9C5FBC0469A2D6D863ED2030742D9A", pt: "FCFACE18E85F91FB", ct:"99FC41875BA19BF1"},
		{ key: "3B9C5FBC5FC83927419FACA730742D9A", pt: "99FC41875BA19BF1", ct:"6868C5C043E660B0"},
		{ key: "787A3F0C5FC83927419FACA7581CE85A", pt: "6868C5C043E660B0", ct:"600B9A14896A12D7"},
		{ key: "787A3F0CD6A22BF0219436B3581CE85A", pt: "600B9A14896A12D7", ct:"C6D1CDD0B674BB9E"},
		{ key: "CE0E8492D6A22BF0219436B39ECD258A", pt: "C6D1CDD0B674BB9E", ct:"7FCD185580F8BB4B"},
		{ key: "CE0E8492565A90BB5E592EE69ECD258A", pt: "7FCD185580F8BB4B", ct:"8279AD3D7089755E"},
		{ key: "BE87F1CC565A90BB5E592EE61CB488B7", pt: "8279AD3D7089755E", ct:"CA52C3075B0CC89B"},
		{ key: "BE87F1CC0D565820940BEDE11CB488B7", pt: "CA52C3075B0CC89B", ct:"FBA81D00BA59FD4F"},
		{ key: "04DE0C830D565820940BEDE1E71C95B7", pt: "FBA81D00BA59FD4F", ct:"FB861C919BD81C95"},
		{ key: "04DE0C83968E44B56F8DF170E71C95B7", pt: "FB861C919BD81C95", ct:"92B872CF95B0572D"},
		{ key: "916E5BAE968E44B56F8DF17075A4E778", pt: "92B872CF95B0572D", ct:"1FE51C21E4F9140A"},
		{ key: "916E5BAE727750BF7068ED5175A4E778", pt: "1FE51C21E4F9140A", ct:"80A9FFB1118FA1F7"},
		{ key: "80E1FA59727750BF7068ED51F50D18C9", pt: "80A9FFB1118FA1F7", ct:"4366A93E2ED91DB2"},
		{ key: "80E1FA595CAE4D0D330E446FF50D18C9", pt: "4366A93E2ED91DB2", ct:"7772428E9683EF07"},
		{ key: "1662155E5CAE4D0D330E446F827F5A47", pt: "7772428E9683EF07", ct:"742A965D80DB3FE4"},
		{ key: "1662155EDC7572E94724D232827F5A47", pt: "742A965D80DB3FE4", ct:"46D7A89009024931"},
		{ key: "1F605C6FDC7572E94724D232C4A8F2D7", pt: "46D7A89009024931", ct:"822528D60248656D"},
		{ key: "1F605C6FDE3D1784C501FAE4C4A8F2D7", pt: "822528D60248656D", ct:"124A0D3C5B53214E"},
		{ key: "44337D21DE3D1784C501FAE4D6E2FFEB", pt: "124A0D3C5B53214E", ct:"2703BB08C50E1BC0"},
		{ key: "44337D211B330C44E20241ECD6E2FFEB", pt: "2703BB08C50E1BC0", ct:"19C8DD1AF291525E"},
		{ key: "B6A22F7F1B330C44E20241ECCF2A22F1", pt: "19C8DD1AF291525E", ct:"BBB04538161ED5D5"},
		{ key: "B6A22F7F0D2DD99159B204D4CF2A22F1", pt: "BBB04538161ED5D5", ct:"DD670945F87D6F8A"},
		{ key: "4EDF40F50D2DD99159B204D4124D2BB4", pt: "DD670945F87D6F8A", ct:"BAE95EB7A1725643"},
		{ key: "4EDF40F5AC5F8FD2E35B5A63124D2BB4", pt: "BAE95EB7A1725643", ct:"4A7030BCE2FEBD61"},
	];
	
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

	testcases.forEach(function(tc, i){
		// console.log("Testcase: " + i);
		var keyBytes = CryptoJS.enc.Hex.parse(tc.key);
		var ptBytes = CryptoJS.enc.Hex.parse(tc.pt);
		var ctBytes = CryptoJS.enc.Hex.parse(tc.ct);
		
		var ct = CryptoJS.TEA.encrypt(ptBytes, keyBytes, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding });
		assert(ct.ciphertext.toString(), tc.ct.toLowerCase(), "ct matches");
		
		var pt = CryptoJS.TEA.decrypt({ciphertext: ctBytes}, keyBytes, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding });
		assert(pt.toString(), tc.pt.toLowerCase(), "pt matches");
	});
})();

console.log("TEA test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
	process.exit(1);
}