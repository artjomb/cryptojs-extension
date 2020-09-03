var fs = require('fs');
var _ = require('lodash');
var Fmd = require('fmd');

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
      var opts = {depends: {'crypto-js/core': 'C'}};
      var deps = [];

      if (options.pack) {

        // Collect all components
        var newDeps = conf;
        do {
          deps = newDeps;
          newDeps = _.chain(deps)
            .map(function(depName) {return options.modules[depName];})
            .flatten()
            .concat(deps)
            .unique()
            .without(name)
            .select(function(depName) {return options.modules[depName];})
            .sortBy(_.identity)
            .sort(function(a, b) {
              return options.modules[a].indexOf(b) >= 0 ? 1 : -1;
            })
            .value();
        } while (!_.isEqual(deps, newDeps));
        console.log(name, deps);

        // Add components as source files -> results a single file
        _.each(this.filesSrc, function(source) {
          _.each(deps, function(depName) {
            if (grunt.file.exists(source + depName + '.js')) {
              sources.push(source + depName + '.js');
            }
          });
          if (grunt.file.exists(source + name + '.js')) sources.push(source + name + '.js');
        }, this);

        // Add any components that aren't modules as external dependencies instead
        _.chain(conf)
          .reject(function(depName) {return options.modules[depName];})
          .map(function(depName) {opts.depends[depName] = null;})
          .commit();

      } else {

        // Find and add self as source
        _.each(this.filesSrc, function(source) {
          if (grunt.file.exists(source + name + '.js')) sources.push(source + name + '.js');
        }, this);

        // Read components and add them as dependecies
        _.each(_.without(conf, name), function(depName) {
          opts.depends[(options.modules[depName] ? './' : '') + depName] = null;
        });

      }

      // Remove duplicates
      sources = _.unique(sources);

      // Add module settings to fmd definition
      modules[name] = [sources, opts];

    }, this);

    // Build packege modules
    var fmd = Fmd(_.defaults({factories: options.factories}, config));
    fs.readdir('node_modules/crypto-js', function(error, files) {
      if (error) {
        grunt.log.writeln('Failed to scan contents of node_modules/crypto-js: ' + error);
        done(false);
        return;
      }
      _.each(files, function(filename) {
        if (/\.js$/.test(filename) && filename !== 'index.js') {
          fmd.vendor(
            'crypto-js/' + filename.replace(/\.js$/, ''),
            filename === 'core.js' ? 'CryptoJS' : null);
        }
      });
      fmd.define(modules).build(function(createdFiles) {done();});
    });

  });
};
