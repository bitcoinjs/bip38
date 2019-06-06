/* global describe, it */

var assert = require('assert')
var bip38 = require('../')
var bs58check = require('bs58check')
var fixtures = require('./fixtures')
var wif = require('wif')

function replaceUnicode (str) {
  var map = {
    '\\u03D2\\u0301\\u{0000}\\u{00010400}\\u{0001F4A9}': '\u03D2\u0301\u{0000}\u{00010400}\u{0001F4A9}'
  }
  if (map[str]) str = map[str]
  return str
}

describe('bip38', function () {
  this.timeout(200000)

  describe('decrypt', function () {
    fixtures.valid.forEach(function (f) {
      it('should decrypt ' + f.description, function () {
        var result = bip38.decrypt(f.bip38, replaceUnicode(f.passphrase))

        assert.strictEqual(wif.encode(0x80, result.privateKey, result.compressed), f.wif)
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

        assert.strictEqual(bip38.encrypt(buffer.slice(1, 33), !!buffer[33], replaceUnicode(f.passphrase)), f.bip38)
      })
    })
  })

  describe('decryptAsync', function () {
    fixtures.valid.forEach(function (f) {
      it('should decrypt ' + f.description, async function () {
        var result = await bip38.decryptAsync(f.bip38, f.passphrase)

        assert.strictEqual(wif.encode(0x80, result.privateKey, result.compressed), f.wif)
      })
    })

    fixtures.invalid.decrypt.forEach(function (f) {
      it('should throw ' + f.description, async function () {
        assert.rejects(async function () {
          await bip38.decryptAsync(f.bip38, f.passphrase)
        }, new RegExp(f.description, 'i'))
      })
    })

    fixtures.invalid.verify.forEach(function (f) {
      it('should throw because ' + f.description, async function () {
        assert.rejects(async function () {
          await bip38.decryptAsync(f.base58, 'foobar')
        }, new RegExp(f.exception))
      })
    })
  })

  describe('encryptAsync', function () {
    fixtures.valid.forEach(function (f) {
      if (f.decryptOnly) return

      it('should encrypt ' + f.description, async function () {
        var buffer = bs58check.decode(f.wif)

        assert.strictEqual(await bip38.encryptAsync(buffer.slice(1, 33), !!buffer[33], f.passphrase), f.bip38)
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
