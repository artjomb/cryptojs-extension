'use strict';

module.exports = {
  build: {
    files: [{
      expand: true,
      cwd: '<%= meta.build %>',
      src: ['*.js'],
      dest: '<%= meta.build %>',
      ext: '.min.js',
      extDot: 'last'
    }]
  }
};
