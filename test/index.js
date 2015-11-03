var assert = require('assert')
var Bip38 = require('../')
var fixtures = require('./fixtures')

/* global beforeEach, describe, it */

describe('bip38', function () {
  this.timeout(70000)

  var bip38
  beforeEach(function () {
    bip38 = new Bip38()
  })

  // describe('decrypt', function () {
  //   fixtures.valid.forEach(function (f) {
  //     it('should decrypt ' + f.description, function () {
  //       assert.equal(bip38.decrypt(f.bip38, f.passphrase), f.wif)
  //     })
  //   })

  //   fixtures.invalid.decrypt.forEach(function (f) {
  //     it('should throw ' + f.description, function () {
  //       assert.throws(function () {
  //         bip38.decrypt(f.bip38, f.passphrase)
  //       }, new RegExp(f.description, 'i'))
  //     })
  //   })

  //   fixtures.invalid.verify.forEach(function (f) {
  //     it('should throw because ' + f.description, function () {
  //       assert.throws(function () {
  //         bip38.decrypt(f.base58, 'foobar')
  //       }, new RegExp(f.exception))
  //     })
  //   })
  // })

  // describe('encrypt', function () {
  //   fixtures.valid.forEach(function (f) {
  //     if (f.decryptOnly) return

  //     it('should encrypt ' + f.description, function () {
  //       assert.equal(bip38.encrypt(f.wif, f.passphrase, f.address), f.bip38)
  //     })
  //   })
  // })

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
