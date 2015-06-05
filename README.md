# Extension for CryptoJS

This extension adds the following algorithms to CryptoJS:

- AES-CMAC ([RFC 4493](https://tools.ietf.org/html/rfc4493)): MAC algorithm based on AES
- AES-SIV ([RFC 5297](https://tools.ietf.org/html/rfc5297)): Synthetic Initialization Vector mode of operation for AES

It can only be used in the browser (for now). The tests run in Node.js in kind of hacky way.

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

# Usage

This extension library depends on [CryptoJS](https://code.google.com/p/crypto-js/), so you need to load it first.

## AES-CMAC

CMAC is a message authentication code algorithm based on AES-128. The key is expected to be 128-bit or 16 byte.

```html
<script type="text/javascript" src="lib/cryptojs-aes.min.js"></script>
<script type="text/javascript" src="build/cmac.min.js"></script>
<script type="text/javascript">
    var key = CryptoJS.enc.Hex.parse('2b7e151628aed2a6abf7158809cf4f3c');
    var message = "This is some message";
    
    var cmac = CryptoJS.algo.CMAC.create(key);
    var mac = cmac.finalize(message);
    
    console.log(mac.toString()); // Hex-encoded MAC
</script>
```

If the message that was passed into `finalize()` is a string it is interpreted as a UTF-8 encoded string. Otherwise, it expects the message to be a `WordArray` which is the basic type of data in CryptoJS.

CMAC also supports a progressive (streaming) way of calculating the MAC:

```javascript
var key = CryptoJS.enc.Hex.parse('2b7e151628aed2a6abf7158809cf4f3c');
var message = "This is some message";

var cmac = CryptoJS.algo.CMAC.create(key);
cmac.update(message.slice(0, 2));
cmac.update(message.slice(2, 9));
cmac.update(message.slice(9, 11));
cmac.update(message.slice(11));
var mac = cmac.finalize();

console.log(mac.toString()); // Hex-encoded MAC
```

## AES-SIV

SIV is an authenticated and deterministic mode of operation for AES. It requires two passes over the plaintext data. It depends internally on AES-CMAC (included in the build file). It works with 256-bit, 384-bit or 512-bit keys. The first half of the key is used for S2V (authentication) and the second half for AES-CTR (encryption).

```html
<script type="text/javascript" src="lib/cryptojs-aes.min.js"></script>
<script type="text/javascript" src="lib/cryptojs-mode-ctr-min.js"></script>
<script type="text/javascript" src="build/siv.min.js"></script>
<script type="text/javascript">
    var key = CryptoJS.enc.Hex.parse('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
    var message = "This is some secret message";
    var additionalData = "This is some additional data";
    
    var siv = CryptoJS.SIV.create(key);
    var ciphertext = siv.encrypt([ additionalData ], message);

    var recoveredPlaintext = siv.decrypt([ additionalData ], ciphertext);
    console.log(recoveredPlaintext.toString() === message);

    // Without additional data
    var ciphertext = siv.encrypt(message);
    var recoveredPlaintext = siv.decrypt(ciphertext);
    console.log(recoveredPlaintext.toString() === message);
</script>
```

Notes:

- The additional data is optional. It is not included in the ciphertext, but used for the authentication tag.
- Additional data and the plaintext message need to be either a UTF-8 encoded string or a `WordArray`.
- The ciphertext is always expected as a `WordArray`.
- The first 16 bytes of the ciphertext contain the authentication tag. The decryption function also expects the authentication tag to be in front of the ciphertext.

# Notes

- The algorithms are completely synchronous. That means that if this is done in the browser, the browser will freeze for the duration of the calculation. JavaScript is always running in the main thread which also handles the rendering. Don't encrypt/MAC large data, because your users won't appreciate it. Use WebWorkers to run the encryption asynchronously in a background thread.