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
            hexAd = $("#siv-ad-type").prop("checked"),
            ad = $(".siv-ad").filter(function(){
                return this.value && this.value.trim().length > 0;
            }).map(function(){
                if (hexAd) {
                    return CryptoJS.enc.Hex.parse(hexCleanup(this.value));
                } else {
                    return this.value;
                }
            }).get(),
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
            result;
        if (this.id === "siv-enc") {
            result = siv.encrypt(ad, msg);
        } else {
            result = siv.decrypt(ad, msg);
        }
        
        if (!result) {
            $("#siv-result").addClass("bad-output").val("\u22a5");
        } else {
            $("#siv-result").removeClass("bad-output").val(insertSpaces(result.toString()));
        }
    });
    
    $("#siv-ad-add").click(function(e){
        e.preventDefault();
        var len = $("siv-ad").length;
        if (len === 0) {
            $("#siv-ad-title").removeClass("hidden");
        }
        if (len < 126) {
            $("#siv-ad-list").append("<input type='text' class='siv-ad max512bit'>");
        }
    });
});