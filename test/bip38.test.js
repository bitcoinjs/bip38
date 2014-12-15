var assert = require('assert')
var Bip38 = require('../')

var fixtures = require('./fixtures')

describe('bip38', function() {
  this.timeout(70000)

  var bip38
  beforeEach(function() {
    bip38 = new Bip38()
  })

  describe('decrypt', function() {
    fixtures.valid.forEach(function(f) {
      it('should decrypt ' + f.description, function() {
        assert.equal(bip38.decrypt(f.bip38, f.passphrase), f.wif)
      })
    })

    fixtures.invalid.forEach(function(f) {
      it('should throw ' + f.description, function() {
        assert.throws(function() {
          bip38.decrypt(f.bip38, f.passphrase)
        }, new RegExp(f.description, 'i'))
      })
    })
  })

  describe('encrypt', function() {
    fixtures.valid.forEach(function(f) {
      if (f.decryptOnly) return

      it('should encrypt ' + f.description, function() {
        assert.equal(bip38.encrypt(f.wif, f.passphrase, f.address), f.bip38)
      })
    })
  })
})
