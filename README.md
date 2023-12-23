# bip38

[![build status](https://secure.travis-ci.org/bitcoinjs/bip38.svg)](http://travis-ci.org/bitcoinjs/bip38)
[![Coverage Status](https://img.shields.io/coveralls/cryptocoinjs/bip38.svg)](https://coveralls.io/r/cryptocoinjs/bip38)
[![Version](http://img.shields.io/npm/v/bip38.svg)](https://www.npmjs.org/package/bip38)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

A JavaScript component that adheres to the [BIP38](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) standard to secure your crypto currency private keys. Fully compliant with Node.js and the browser (via Browserify).


## Why?
BIP38 is a standard process to encrypt Bitcoin and crypto currency private keys that is impervious to brute force attacks thus protecting the user.


## Package Info
- homepage: [http://cryptocoinjs.com/modules/currency/bip38/](http://cryptocoinjs.com/modules/currency/bip38/)
- github: [https://github.com/cryptocoinjs/bip38](https://github.com/cryptocoinjs/bip38)
- tests: [https://github.com/cryptocoinjs/bip38/tree/master/test](https://github.com/cryptocoinjs/bip38/tree/master/test)
- issues: [https://github.com/cryptocoinjs/bip38/issues](https://github.com/cryptocoinjs/bip38/issues)
- license: **MIT**
- versioning: [http://semver-ftw.org](http://semver-ftw.org)


## Usage

### Installation

    npm install --save bip38


### Async methods

Async methods are available. Using them will be slower but will free up the event loop. You can set `asyncTickInterval` in the scryptParams to control the maximum amount of time the function can block.

   `N` is cpu/mem work factor (power of 2 e.g. 2**18)
   `r` is block size (8 is common), fine-tunes sequential memory read size and performance
   `p` is parallelization factor (1 is common)
   `dkLen` is output key length in bytes e.g. 32.
   `asyncTick` - (default: 10) max time in ms for which async function can block execution
   `maxmem` - (default: `1024 ** 3 + 1024` aka 1GB+1KB). A limit that the app could use for scrypt
   `onProgress` - callback function that would be executed for progress report

### API
### encrypt(buffer, compressed, passphrase[, progressCallback, scryptParams])

``` javascript
import { encrypt } from "bip38"
import wif from "wif"

const myWifString = '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'
const decoded = wif.decode(myWifString)

const encryptedKey = encrypt(decoded.privateKey, decoded.compressed, 'TestingOneTwoThree')
console.log(encryptedKey)
// => '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg'
```


### decrypt(encryptedKey, passphrase[, progressCallback, scryptParams])

``` javascript
import { decrypt } from "bip38"
import wif from "wif"

var encryptedKey = '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg'
var decryptedKey = decrypt(encryptedKey, 'TestingOneTwoThree', function (percent) {
  console.log(percent) // will print the percent every time current increases by 1000
})

console.log(wif.encode(0x80, decryptedKey.privateKey, decryptedKey.compressed))
// => '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'
```


# References
- https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
- https://github.com/pointbiz/bitaddress.org/issues/56 (Safari 6.05 issue)
- https://github.com/casascius/Bitcoin-Address-Utility/tree/master/Model
- https://github.com/nomorecoin/python-bip38-testing/blob/master/bip38.py
- https://github.com/pointbiz/bitaddress.org/blob/master/src/ninja.key.js
