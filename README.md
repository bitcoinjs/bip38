bip38
=====

[![build status](https://secure.travis-ci.org/cryptocoinjs/bip38.png)](http://travis-ci.org/cryptocoinjs/bip38)
[![Coverage Status](https://img.shields.io/coveralls/cryptocoinjs/bip38.svg)](https://coveralls.io/r/cryptocoinjs/bip38)
[![Version](http://img.shields.io/npm/v/bip38.svg)](https://www.npmjs.org/package/bip38)

[![browser support](https://ci.testling.com/cryptocoinjs/bip38.png)](https://ci.testling.com/cryptocoinjs/bip38)

A JavaScript component that adheres to the [BIP38](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) standard to secure your crypto currency private keys. Fully compliant with Node.js and the browser (via Browserify).

Official documentation:

http://cryptocoinjs.com/modules/currency/bip38/


## Examples

```javascript
var BIP38 = require('bip38')
var bip38 = new BIP38()
  
bip38.encrypt('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss', 'qwerty', '1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN')
// => 6PRSrLgB2Znxs8C7NgzeZgPLGV3xD3GrcAvoH7NMpVcMSpbrCTtrnj6zmT
  
bip38.decrypt('6PRSrLgB2Znxs8C7NgzeZgPLGV3xD3GrcAvoH7NMpVcMSpbrCTtrnj6zmT', 'qwerty')
// => '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'
```
