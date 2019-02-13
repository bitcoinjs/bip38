/* global describe, it */

var assert = require('assert')
var bip38 = require('../')
var bs58check = require('bs58check')
var fixtures = require('./fixtures')
var wif = require('wif')

describe('bip38', function () {
  this.timeout(200000)

  describe('decrypt', function () {
    fixtures.valid.forEach(function (f) {
      it('should decrypt ' + f.description, function () {
        var result = bip38.decrypt(f.bip38, f.passphrase, null, null, f.network)
        var prefix = f.network ? f.network.private : 0x80
        assert.equal(wif.encode(prefix, result.privateKey, result.compressed), f.wif)
      })
    })

    fixtures.invalid.decrypt.forEach(function (f) {
      it('should throw ' + f.description, function () {
        assert.throws(function () {
          bip38.decrypt(f.bip38, f.passphrase)
        }, new RegExp(f.description, 'i'))
      })
    })

    fixtures.invalid.verify.forEach(function (f) {
      it('should throw because ' + f.description, function () {
        assert.throws(function () {
          bip38.decrypt(f.base58, 'foobar')
        }, new RegExp(f.exception))
      })
    })
  })

  describe('encrypt', function () {
    fixtures.valid.forEach(function (f) {
      if (f.decryptOnly) return

      it('should encrypt ' + f.description, function () {
        var buffer = bs58check.decode(f.wif)

        assert.equal(bip38.encrypt(buffer.slice(1, 33), !!buffer[33], f.passphrase, null, null, f.network), f.bip38)
      })
    })
  })

  describe('verify', function () {
    fixtures.valid.forEach(function (f) {
      it('should return true for ' + f.bip38, function () {
        assert(bip38.verify(f.bip38))
      })
    })

    fixtures.invalid.verify.forEach(function (f) {
      it('should return false for ' + f.description, function () {
        assert(!bip38.verify(f.base58))
      })
    })
  })
})
