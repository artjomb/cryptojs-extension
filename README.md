# Extension for CryptoJS

This extension includes the following algorithms to CryptoJS:

- AES-CMAC ([RFC 4493](https://tools.ietf.org/html/rfc4493)): MAC algorithm based on AES
- AES-SIV ([RFC 5297](https://tools.ietf.org/html/rfc5297)): Synthetic Initialization Vector mode of operation for AES

# How to build

```
$ npm install
$ npm run build
```

# How to run tests

Tests are run on the build files, so it is necessary to build them first. Then the tests are invoked through

```
npm run test
```