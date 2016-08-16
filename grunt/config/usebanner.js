'use strict';

module.exports = {
  build: {
    options: {
      banner: '/*\n * The MIT License\n *\n * (MIT)Copyright (c) 2015 artjomb\n */'
    },
    files: {
      src: ['<%= meta.build %>*.min.js']
    }
  }
};
