var Bip38 = null

//node.js or mochify
if (typeof module != 'undefined' && module.exports) {
  Bip38 = require('../');
  require('terst');
} else { //manually running browser-test.js
  Bip38 = window.mod;
}

var assert = require('assert')

var fixtures = require('./fixtures/bip38')

describe('bip38', function() {
  describe('> when valid', function() {
    fixtures.valid.forEach(function(f) {
      it('should encrypt and decrypt ' + f.description, function() {
        var bip38 = new Bip38()
        if (!f.decryptOnly)
          EQ (bip38.encrypt(f.wif, f.passphrase, f.address), f.bip38)
        EQ (bip38.decrypt(f.bip38, f.passphrase), f.wif)
      })
    })
  })

  describe('> when invalid', function() {
    fixtures.invalid.forEach(function(f) {
      it('should throw ' + f.description, function() {
        var bip38 = new Bip38()
        assert.throws(function() {
          bip38.decrypt(f.bip38, f.passphrase, f.address)
        }, new RegExp(f.description, 'i'))
      })
    })
  })
})
