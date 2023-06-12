# Extension for CryptoJS

This extension adds the following algorithms to CryptoJS:

- AES-CMAC ([RFC 4493](https://tools.ietf.org/html/rfc4493)): MAC algorithm based on AES
- AES-SIV ([RFC 5297](https://tools.ietf.org/html/rfc5297)): Synthetic Initialization Vector mode of operation for AES
- AES-EAX ([eax.pdf](http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf)): EAX Mode of Operation for AES
- CFB ([NIST Special Publication 800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf)): Block cipher mode of operation for confidentiality with a variable segment size

It can be used both in Node.js and the browser.

## Online "calculator"

There is an online calculator that enables you to try out AES-CMAC and AES-SIV in the browser: http://artjomb.github.io/cryptojs-extension/

## How to build

Make sure you have `npm install -g grunt-cli` installed on your system.

```
$ npm install
$ npm run build
```

## How to run tests

Tests are run on the build files, so it is necessary to build them first. Then the tests are invoked through

```
npm run test
```

## Usage

This extension library depends on [CryptoJS](https://code.google.com/p/crypto-js/), so you need to load it first.

### AES-CMAC

CMAC is a message authentication code algorithm based on AES-128. The key is expected to be 128-bit or 16 byte.

```html
<script type="text/javascript" src="lib/cryptojs-aes.min.js"></script>
<script type="text/javascript" src="build/cmac.min.js"></script>
<script type="text/javascript">
    var key = CryptoJS.enc.Hex.parse('2b7e151628aed2a6abf7158809cf4f3c');
    var message = "This is some message";

    var mac = CryptoJS.CMAC(key, message);

    console.log(mac.toString()); // Hex-encoded MAC
</script>
```

If the message is a string, it is interpreted as a UTF-8 encoded string. Otherwise, it expects the message to be a `WordArray` which is the basic data type in CryptoJS.

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

### AES-SIV

SIV is an authenticated and deterministic mode of operation for AES. It requires two passes over the plaintext data. It depends internally on AES-CMAC (included in the build file). It works with 256-bit, 384-bit or 512-bit keys. The first half of the key is used for S2V (authentication) and the second half for AES-CTR (encryption).

```html
<script type="text/javascript" src="lib/cryptojs-aes.min.js"></script>
<script type="text/javascript" src="lib/cryptojs-mode-ctr.min.js"></script>
<script type="text/javascript" src="build/siv.min.js"></script>
<script type="text/javascript">
    var key = CryptoJS.enc.Hex.parse('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
    var message = "This is some secret message";
    var additionalData = "This is some additional data";

    var siv = CryptoJS.SIV.create(key);
    var ciphertext = siv.encrypt([ additionalData ], message);

    var recoveredPlaintext = siv.decrypt([ additionalData ], ciphertext);
    console.log(recoveredPlaintext.toString(CryptoJS.enc.Utf8) === message);

    // Without additional data
    var ciphertext = siv.encrypt(message);
    var recoveredPlaintext = siv.decrypt(ciphertext);
    console.log(recoveredPlaintext.toString(CryptoJS.enc.Utf8) === message);
</script>
```

Notes:

- The additional data is optional. It is not included in the ciphertext, but used for the authentication tag.
- Additional data and the plaintext message need to be either a UTF-8 encoded string or a `WordArray`.
- The ciphertext is always expected as a `WordArray`.
- The first 16 bytes of the ciphertext contain the authentication tag. The decryption function also expects the authentication tag to be in front of the ciphertext.

### AES-EAX

EAX is a authenticated mode based on AES and CMAC. It requires the use of a nonce, but can be implemented as a single pass (plaintext needs to be passed in only once). It works either with a single key with 128, 192 or 256 bit or with a double sized key where the first half will be used for CMAC and the second half for CTR (actual encryption).

```html
<script type="text/javascript" src="lib/cryptojs-aes.min.js"></script>
<script type="text/javascript" src="lib/cryptojs-mode-ctr.min.js"></script>
<script type="text/javascript" src="build/eax.min.js"></script>
<script type="text/javascript">
    var key = CryptoJS.enc.Hex.parse('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0');
    var nonce = CryptoJS.lib.WordArray.random(16);
    var message = "This is some secret message";
    var additionalData = "This is some additional (authenticated) data";

    var eax = CryptoJS.EAX.create(key);
    var ciphertext = eax.encrypt(message, nonce, [ additionalData ]);

    var recoveredPlaintext = eax.decrypt(ciphertext, nonce, [ additionalData ]);
    console.log(recoveredPlaintext.toString(CryptoJS.enc.Utf8) === message);

    // Without additional data
    var ciphertext = eax.encrypt(message, nonce);
    var recoveredPlaintext = eax.decrypt(ciphertext, nonce);
    console.log(recoveredPlaintext.toString(CryptoJS.enc.Utf8) === message);
</script>
```

It is also possible to use a progressive encryption/decryption:

```javascript
var key = CryptoJS.enc.Hex.parse('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0');
var nonce = CryptoJS.lib.WordArray.random(16);
var message = "This is some secret message";
var additionalData = "This is some additional (authenticated) data";

var eax = CryptoJS.EAX.create(key);

// AAD must be called before the actual encryption begins
eax.updateAAD(additionalData);
eax.initCrypt(true /* encryption */, nonce);

var ct1 = eax.update("This ");
var ct2 = eax.update("is some ");
var ct3 = eax.update("secret message");
var ct4 = eax.finalize();

ct1.concat(ct2);
ct3.concat(ct4);

// the same object can be reused as long as the key doesn't need to change
eax.updateAAD(additionalData);
eax.initCrypt(false /* decryption */, nonce);

var pt1 = eax.update(ct1);
var pt2 = eax.finalize(ct3);

if (pt2 !== false) {
    console.log("Valid: " + pt1.concat(pt2).toString(CryptoJS.enc.Utf8));
} else {
    console.log("Authentication tag didn't match");
}
```

### CFB

The Cipher Feedback Mode is a mode of operation for confidentiality with a shift register. This project contains two variants of the CFB mode. `CFBw` only supports segment sizes of a multiple of 32 bit (word size) up to the block size of the underlying block cipher. `CFBb` is more flexible in that it supports any segment size from 1 bit up to the block size with the current limitation that the block size must be divisible by the segment size.

CryptoJS's `CFB` implementation doesn't support a custom segment size and only uses full block segments.

Example usage of `CFBb` without padding:

```html
<script type="text/javascript" src="lib/cryptojs-aes.min.js"></script>
<script type="text/javascript" src="build/mode-cfb-b.min.js"></script>
<script type="text/javascript">
    var key = CryptoJS.enc.Hex.parse('2b7e151628aed2a6abf7158809cf4f3c');
    var iv = CryptoJS.lib.WordArray.random(128/8);
    var mode = CryptoJS.mode.CFBb;
    var padding = {
        pad: function () {},
        unpad: function () {}
    }; // NoPadding
    var segmentSize = 8; // bits; can also be 1, 2, 4, 16, 32, 64, 128 for AES

    var message = "This is some secret message";

    var encrypted = CryptoJS.AES.encrypt(message, key, {
        iv: iv,
        mode: mode,
        padding: padding,
        segmentSize: segmentSize
    });
    var recoveredPlaintext = CryptoJS.AES.decrypt(encrypted, key, {
        iv: iv,
        mode: mode,
        padding: padding,
        segmentSize: segmentSize
    });

    console.log(recoveredPlaintext.toString(CryptoJS.enc.Utf8) === message);
</script>
```

Example usage of `CFBw` with default PKCS#7 padding:

```html
<script type="text/javascript" src="lib/cryptojs-aes.min.js"></script>
<script type="text/javascript" src="build/mode-cfb-w.min.js"></script>
<script type="text/javascript">
    var key = CryptoJS.enc.Hex.parse('2b7e151628aed2a6abf7158809cf4f3c');
    var iv = CryptoJS.lib.WordArray.random(128/8);
    var mode = CryptoJS.mode.CFBw;
    var segmentSize = 32; // bits; can also be 64 or 128 for AES

    var message = "This is some secret message";

    var encrypted = CryptoJS.AES.encrypt(message, key, {
        iv: iv,
        mode: mode,
        segmentSize: segmentSize
    });
    var recoveredPlaintext = CryptoJS.AES.decrypt(encrypted, key, {
        iv: iv,
        mode: mode,
        segmentSize: segmentSize
    });

    console.log(recoveredPlaintext.toString(CryptoJS.enc.Utf8) === message);
</script>
```

Notes:

- Keep in mind that the standard PKCS#7 padding only works reliably if the block size is a multiple of the block size. Example: `segmentSize = 96` and `blockSize = 128`.
 - Use `NoPadding` for segment sizes of 8 bit or smaller.
 - Otherwise create your own padding.
 - Don't even think about using segment sizes like 40 bit or 96 bit, because that is currently broken.

## Notes

- The algorithms are completely synchronous. That means that if this is done in the browser, the browser will freeze for the duration of the calculation. JavaScript is always running in the main thread which also handles the rendering. Don't encrypt/MAC large data, because your users won't appreciate it. Use WebWorkers to run the encryption asynchronously in a background thread.
