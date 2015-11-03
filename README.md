bip38
=====

[![build status](https://secure.travis-ci.org/bitcoinjs/bip38.svg)](http://travis-ci.org/bitcoinjs/bip38)
[![Coverage Status](https://img.shields.io/coveralls/cryptocoinjs/bip38.svg)](https://coveralls.io/r/cryptocoinjs/bip38)
[![Version](http://img.shields.io/npm/v/bip38.svg)](https://www.npmjs.org/package/bip38)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

A JavaScript component that adheres to the [BIP38](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) standard to secure your crypto currency private keys. Fully compliant with Node.js and the browser (via Browserify).


Why?
----

BIP38 is a standard process to encrypt Bitcoin and crypto currency private keys that is imprevious to brute force attacks thus protecting the user.


Package Info
------------
- homepage: [http://cryptocoinjs.com/modules/currency/bip38/](http://cryptocoinjs.com/modules/currency/bip38/)
- github: [https://github.com/cryptocoinjs/bip38](https://github.com/cryptocoinjs/bip38)
- tests: [https://github.com/cryptocoinjs/bip38/tree/master/test](https://github.com/cryptocoinjs/bip38/tree/master/test)
- issues: [https://github.com/cryptocoinjs/bip38/issues](https://github.com/cryptocoinjs/bip38/issues)
- license: **MIT**
- versioning: [http://semver-ftw.org](http://semver-ftw.org)


Usage
-----

### Installation

    npm install --save bip38


API
---

### Bip38([versions])

Constructor that creates a new `Bip38` instance. 

- **versions**: optional parameter to set the versions. Defaults to Bitcoin.


### versions

A field that accepts an object for the address version. This easily allows you to support altcoins. Defaults to Bitcoin values.


**example:**

```js
var Bip38 = require('bip38')

var privateKeyWif = '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'

var bip38 = new Bip38()

// not necessary, as Bitcoin is supported by default
bip38.versions = {
	private: 0x80, 
  public: 0x0
}
bip38.encrypt(privateKeyWif, "super-secret", "1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB"})
```

### scryptParams

A field that accepts an object with the follow properties: `N`, `r`, and `p` to control the [scrypt](https://github.com/cryptocoinjs/scryptsy). The
BIP38 standard suggests `N = 16384`, `r = 8`, and `p = 8`. However, this may yield unacceptable performance on a mobile phone. If you alter these parameters, it wouldn't be wise to suggest to your users that your import/export encrypted keys are BIP38 compatible. If you do, you may want to alert them of your parameter changes.

**example:**

```js
bip38.scryptParams = {
  N: 8192, 
  r: 8, 
  p: 8
}
```


### encrypt(wif, passphrase, address, progressCallback)

A method that encrypts the private key. `wif` is the string value of the wallet import format key. `passphrase` the passphrase to encrypt the key with. `address` is the public address.
`progressCallback` is a function that receives an object in the form of: 
{current: 1000, total: 262144, percent: 0.3814697265625}


Returns the encrypted string.

**example**:

```js
var Bip38 = require('bip38')

var privateKeyWif = '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'

var bip38 = new Bip38()
var encrypted = bip38.encrypt(privateKeyWif, 'TestingOneTwoThree', "1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB", function (status) {
    console.log(status.percent) // Will print the precent every time current increases by 1000
})
console.log(encrypted) 
// => 6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg
```


### decrypt(encryptedKey, passhprase, progressCallback)

A method that decrypts the encrypted string. `encryptedKey` is the string value of the encrypted key. `passphrase` is the passphrase to decrypt the key with.
`progressCallback` is a function that receives an object in the form of: 
{current: 1000, total: 262144, percent: 0.3814697265625}


```js
var Bip38 = require('bip38')

var encryptedKey = '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg'

var bip38 = new Bip38()
var privateKeyWif = bip38.decrypt(encryptedKey, 'TestingOneTwoThree', function (status) {
    console.log(status.percent) // Will print the precent every time current increases by 1000
})
console.log(privateKeyWif) 
// =>  '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'
```

**note:** To check for an invalid password, you'll want to generate the public address from the output of the `decrypt()` function. If it doesn't equal the expected address or the address checksum, then chances are, it's an invalid password. The reason that this logic was not included is because it would have required a lot of dependencies: `ECKey` and `Address`. Currently, `ECKey` is pretty heavy on dependencies.



References
----------
- https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
- https://github.com/pointbiz/bitaddress.org/issues/56 (Safari 6.05 issue)
- https://github.com/casascius/Bitcoin-Address-Utility/tree/master/Model
- https://github.com/nomorecoin/python-bip38-testing/blob/master/bip38.py
- https://github.com/pointbiz/bitaddress.org/blob/master/src/ninja.key.js 

