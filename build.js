var fs = require("fs"),
	UglifyJS = require("uglify-js"),
	buildJson = JSON.parse(fs.readFileSync("./build.json", "utf8"));

if (buildJson.rollups) {
	for (var rollup in buildJson.rollups) {
		if (buildJson.rollups.hasOwnProperty(rollup)) {
			var container = "";
			var deps = buildJson.rollups[rollup];
			deps.forEach(function(dep){
				container += fs.readFileSync("./src/"+dep+".js", "utf8");
			});
			container += fs.readFileSync("./src/"+rollup+".js", "utf8");
			
			var minContainer = UglifyJS.minify(container, {fromString: true});
			
			fs.writeFileSync("./build/"+rollup+".js", container);
			fs.writeFileSync("./build/"+rollup+".min.js", buildJson.licenseHeader + minContainer.code);
		}
	}
}