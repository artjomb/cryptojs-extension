$(function(){
    function hexCleanup(s){
        return s.replace(/0x/g, "")
                .replace(/ /g, "")
                .toLowerCase();
    }
    
    function insertSpaces(s){
        var ns = "";
        var width = 8;
        for (var i = 0; i < s.length; i += width) {
            ns += s.slice(i, i+width) + " ";
        }
        return ns;
    }
    
    $("#cmac-calc").click(function(){
        var msg = $("#cmac-msg").val(),
            key = $("#cmac-key").val(),
            hexMsg = $("#cmac-msg-type").prop("checked"),
            hexKey = $("#cmac-key-type").prop("checked");
        
        if (hexMsg) {
            msg = hexCleanup(msg);
            msg = CryptoJS.enc.Hex.parse(msg);
        }
        if (hexKey) {
            key = hexCleanup(key);
            key = CryptoJS.enc.Hex.parse(key);
        }
        
        var result = CryptoJS.CMAC(key, msg);
        
        $("#cmac-result").val(insertSpaces(result.toString()));
    });
    
    $("#siv-enc, #siv-dec").click(function(){
        var msg = $("#siv-input").val(),
            key = $("#siv-key").val(),
            hexMsg = $("#siv-input-type").prop("checked"),
            hexKey = $("#siv-key-type").prop("checked");
        
        if (hexMsg) {
            msg = hexCleanup(msg);
            msg = CryptoJS.enc.Hex.parse(msg);
        }
        if (hexKey) {
            key = hexCleanup(key);
            key = CryptoJS.enc.Hex.parse(key);
        }
        
        var siv = CryptoJS.SIV.create(key),
            result,
            ad = ["a"];
        if (this.id === "siv-enc") {
            result = siv.encrypt(ad, msg);
        } else {
            result = siv.decrypt(ad, msg);
        }
        
        $("#siv-result").val(insertSpaces(result.toString()));
    });
});