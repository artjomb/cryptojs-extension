'use strict';

var _ = require('lodash');

var modules = {
  'enc-bin': [],
  'common-bit-ops': [],
  'random': [],
  'mode-cfb-w': [],
  'common': ['common-bit-ops'],
  'mode-cfb-b': ['common-bit-ops'],
  'cmac': ['common-bit-ops', 'common'],
  'siv': ['common-bit-ops', 'common', 'cmac'],
  'eax': ['common-bit-ops', 'common', 'cmac'],
  'hkdf': [],
  'blowfish': [],
  'gost-streebog': [],
  'gost28147': [],
  'spongent': [],
  'neeva': [],
  'tea': []
};

module.exports = {
  build: {
    files: [{
      expand: false,
      cwd: '<%= meta.cwd %>',
      src: ['<%= meta.source %>'],
      dest: '<%= meta.build %>'
    }],
    options: {
      factories: ['amd', 'global'],
      pack: true,
      modules: _.extend({}, modules, {all: _.keys(modules)})
    }
  },
  buildNode: {
    files: [{
      expand: false,
      cwd: '<%= meta.cwd %>',
      src: ['<%= meta.source %>'],
      dest: '<%= meta.buildNode %>'
    }],
    options: {
      factories: ['commonjs'],
      modules: _.extend({}, modules, {index: _.keys(modules)})
    }
  }
};
