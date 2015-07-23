/* 
 * The MIT License (MIT)
 * 
 * Copyright (c) 2015 artjomb
 */

var fs = require("fs"),
    UglifyJS = require("uglify-js"),
    buildJson = JSON.parse(fs.readFileSync("./build.json", "utf8")),
    done = {};

function resolve(depContainer, name) {
    if (done.hasOwnProperty(name)){
        return depContainer[name];
    }
    
    var deps = depContainer[name];
    var resolvedDeps = [];
    deps.forEach(function(dep){
        resolve(depContainer, dep).forEach(function(dep){
            resolvedDeps.push(dep);
        });
        resolvedDeps.push(dep);
    });
    
    // remove duplicates; see: http://stackoverflow.com/a/9229821 by georg
    resolvedDeps = resolvedDeps.filter(function(item, pos, self) {
        return self.indexOf(item) == pos;
    });
    
    // remove non-existing files (that shouldn't happen)
    resolvedDeps = resolvedDeps.filter(function(item) {
        return fs.existsSync("./src/" + item + ".js");
    });
    
    depContainer[name] = resolvedDeps;
    
    var container = "";
    resolvedDeps.forEach(function(dep){
        container += fs.readFileSync("./src/"+dep+".js", "utf8") + "\n\n";
    });
    if (fs.existsSync("./src/"+name+".js")) {
        container += fs.readFileSync("./src/"+name+".js", "utf8");
    }
    
    var minContainer = UglifyJS.minify(container, {fromString: true});
    
    fs.writeFileSync("./build/"+name+".js", container);
    fs.writeFileSync("./build/"+name+".min.js", buildJson.licenseHeader + minContainer.code);
    
    done[name] = true;
    return depContainer[name];
}

if (buildJson.rollups) {
    var keys = [];
    for (var rollup in buildJson.rollups) {
        if (buildJson.rollups.hasOwnProperty(rollup)) {
            resolve(buildJson.rollups, rollup);
            keys.push(rollup);
        }
    }
    buildJson.rollups["all"] = keys;
    resolve(buildJson.rollups, "all");
}