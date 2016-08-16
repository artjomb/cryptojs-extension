var _ = require('lodash');
var fmd = require('fmd');

module.exports = function(grunt) {

  grunt.registerMultiTask('modularize', function () {
    var options = this.options();
    var done = this.async();
    var modules = {};
    var config = {
      target: this.files[0].dest,
      factories: ['commonjs', 'amd', 'global'],
      trim_whitespace: true,
      new_line: 'unix',
      indent: 2
    };

    // Prepare Factory-Module-Definition settings
    _.each(options.modules, function(conf, name) {
      var sources = [];
      var opts = {depends: {'crypto-js': 'C'}};
      var deps = [];

      if (options.pack) {

        // Collect all components
        deps = _.chain(conf)
          .map(function(depName) {return options.modules[depName];})
          .flatten()
          .unique()
          .without(name)
          .sort(function(a, b) {
            return options.modules[a].indexOf(b) >= 0 ? 1 : -1;
          })
          .value();

        // Add components as source files -> results a single file
        _.each(this.filesSrc, function(source) {
          _.each(deps, function(depName) {
            if (grunt.file.exists(source + depName + '.js')) {
              sources.push(source + depName + '.js');
            }
          });
          if (grunt.file.exists(source + name + '.js')) sources.push(source + name + '.js');
        }, this);

      } else {

        // Find and add self as source
        _.each(this.filesSrc, function(source) {
          if (grunt.file.exists(source + name + '.js')) sources.push(source + name + '.js');
        }, this);

        // Read components and add them as dependecies
        _.each(_.without(conf, name), function (value) {
          opts.depends['./' + value] = null;
        });

      }

      // Remove duplicates
      sources = _.unique(sources);

      // Add module settings to fmd definition
      modules[name] = [sources, opts];

    }, this);

    // Build packege modules
    fmd(_.defaults({factories: options.factories}, config))
      .vendor('crypto-js', 'CryptoJS')
      .define(modules)
      .build(function(createdFiles) {done();});
  });
};
