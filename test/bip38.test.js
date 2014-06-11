var assert = require('assert')
var Bip38 = require('../')

var fixtures = require('./fixtures/bip38')

describe('bip38', function() {
  describe('> when valid', function() {
    fixtures.valid.forEach(function(f) {
      it('should encrypt and decrypt ' + f.description, function() {
        var bip38 = new Bip38()
        if (!f.decryptOnly)
          assert.equal(bip38.encrypt(f.wif, f.passphrase, f.address), f.bip38)
        assert.equal(bip38.decrypt(f.bip38, f.passphrase), f.wif)
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
