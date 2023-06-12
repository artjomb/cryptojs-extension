var fs = require("fs");
var CryptoJS = require('crypto-js/core');
require('../build_node/eax.js');

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

var vectors = [
    // From http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf ...
    {
        msg: "",
        key: "233952DEE4D5ED5F9B9C6D6FF80FF478",
        nonce: "62EC67F9C3A4A407FCB2A8C49031A8B3",
        header: "6BFB914FD07EAE6B",
        ct: "E037830E8389F27B025A2D6527E79D01"
    },
    {
        msg: "F7FB",
        key: "91945D3F4DCBEE0BF45EF52255F095A4",
        nonce: "BECAF043B0A23D843194BA972C66DEBD",
        header: "FA3BFD4806EB53FA",
        ct: "19DD5C4C9331049D0BDAB0277408F67967E5"
    },
    {
        msg: "1A47CB4933",
        key: "01F74AD64077F2E704C0F60ADA3DD523",
        nonce: "70C3DB4F0D26368400A10ED05D2BFF5E",
        header: "234A3463C1264AC6",
        ct: "D851D5BAE03A59F238A23E39199DC9266626C40F80"
    },
    {
        msg: "481C9E39B1",
        key: "D07CF6CBB7F313BDDE66B727AFD3C5E8",
        nonce: "8408DFFF3C1A2B1292DC199E46B7D617",
        header: "33CCE2EABFF5A79D",
        ct: "632A9D131AD4C168A4225D8E1FF755939974A7BEDE"
    },
    {
        msg: "40D0C07DA5E4",
        key: "35B6D0580005BBC12B0587124557D2C2",
        nonce: "FDB6B06676EEDC5C61D74276E1F8E816",
        header: "AEB96EAEBE2970E9",
        ct: "071DFE16C675CB0677E536F73AFE6A14B74EE49844DD"
    },
    {
        msg: "4DE3B35C3FC039245BD1FB7D",
        key: "BD8E6E11475E60B268784C38C62FEB22",
        nonce: "6EAC5C93072D8E8513F750935E46DA1B",
        header: "D4482D1CA78DCE0F",
        ct: "835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F"
    },
    {
        msg: "8B0A79306C9CE7ED99DAE4F87F8DD61636",
        key: "7C77D6E813BED5AC98BAA417477A2E7D",
        nonce: "1A8C98DCD73D38393B2BF1569DEEFC19",
        header: "65D2017990D62528",
        ct: "02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2"
    },
    {
        msg: "1BDA122BCE8A8DBAF1877D962B8592DD2D56",
        key: "5FFF20CAFAB119CA2FC73549E20F5B0D",
        nonce: "DDE59B97D722156D4D9AFF2BC7559826",
        header: "54B9F04E6A09189A",
        ct: "2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A"
    },
    {
        msg: "6CF36720872B8513F6EAB1A8A44438D5EF11",
        key: "A4A4782BCFFD3EC5E7EF6D8C34A56123",
        nonce: "B781FCF2F75FA5A8DE97A9CA48E522EC",
        header: "899A175897561D7E",
        ct: "0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700"
    },
    {
        msg: "CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7",
        key: "8395FCF1E95BEBD697BD010BC766AAC3",
        nonce: "22E7ADD93CFC6393C57EC0B3C17D6B44",
        header: "126735FCC320D25A",
        ct: "CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E"
    },
];

vectors.forEach(function(vec, i){
    var keyBytes = CryptoJS.enc.Hex.parse(vec.key),
        msgBytes = CryptoJS.enc.Hex.parse(vec.msg),
        nonceBytes = CryptoJS.enc.Hex.parse(vec.nonce),
        headerBytes = CryptoJS.enc.Hex.parse(vec.header);

    // encryption test
    var eax = CryptoJS.EAX.create(keyBytes);
    var ct = eax.encrypt(msgBytes, nonceBytes, [headerBytes]);
    assert(ct.toString(), vec.ct.toLowerCase(), "ciphertext match ["+i+"]");

    // decryption test with verification
    var pt = eax.decrypt(ct, nonceBytes, [headerBytes]);
    assert(pt.toString(), vec.msg.toLowerCase(), "plaintext match ["+i+"]");

    // tampering detection test
    ct = eax.encrypt(msgBytes, nonceBytes, [headerBytes]);
    ct.words[2] ^= 8
    pt = eax.decrypt(ct, nonceBytes, [headerBytes]);
    assert(pt, false, "tampering detected ["+i+"]");

    // testing without additional data
    ct = eax.encrypt(msgBytes, nonceBytes);
    pt = eax.decrypt(ct, nonceBytes);
    assert(pt.toString(), vec.msg.toLowerCase(), "plaintext match w/o AD ["+i+"]");

    // testing with multiple additional data
    ct = eax.encrypt(msgBytes, nonceBytes, [headerBytes, headerBytes, headerBytes, CryptoJS.lib.WordArray.create()]);
    pt = eax.decrypt(ct, nonceBytes, [headerBytes, headerBytes, headerBytes]);
    assert(pt.toString(), vec.msg.toLowerCase(), "plaintext match w/ 3*AD ["+i+"]");
});

console.log("EAX test - passed: " + stats.passed + ", failed: " + stats.failed + ", total: " + (stats.passed+stats.failed) + "\n");

if (stats.failed > 0) {
    process.exit(1);
}
