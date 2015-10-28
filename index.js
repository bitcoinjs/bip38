var aes = require('browserify-aes')
var assert = require('assert')
var createHash = require('create-hash')
var cs = require('coinstring')
var scrypt = require('scryptsy')
var xor = require('buffer-xor')

var ecurve = require('ecurve')
var curve = ecurve.getCurveByName('secp256k1')

var BigInteger = require('bigi')

// SHA256(SHA256(buffer))
function sha256x2 (buffer) {
  buffer = createHash('sha256').update(buffer).digest()
  return createHash('sha256').update(buffer).digest()
}

function Bip38 (versions) {
  if (!(this instanceof Bip38)) return new Bip38()

  // default to Bitcoin WIF versions
  this.versions = versions || { private: 0x80 }

  // BIP38 recommended
  this.scryptParams = {
    N: 16384,
    r: 8,
    p: 8
  }
}

Bip38.prototype.encryptRaw = function (buffer, compressed, passphrase, saltAddress, progressCallback) {
  assert.equal(buffer.length, 32, 'Invalid private key length')

  var secret = new Buffer(passphrase, 'utf8')
  var salt = sha256x2(saltAddress).slice(0, 4)

  var N = this.scryptParams.N
  var r = this.scryptParams.r
  var p = this.scryptParams.p

  var scryptBuf = scrypt(secret, salt, N, r, p, 64, progressCallback)
  var derivedHalf1 = scryptBuf.slice(0, 32)
  var derivedHalf2 = scryptBuf.slice(32, 64)

  var xorBuf = xor(buffer, derivedHalf1)
  var cipher = aes.createCipheriv('aes-256-ecb', derivedHalf2, new Buffer(0))
  cipher.setAutoPadding(false)
  cipher.end(xorBuf)

  var cipherText = cipher.read()

  // 0x01 + 0x42 + flagByte + salt + cipherText
  var flagByte = compressed ? 0xe0 : 0xc0
  var prefix = new Buffer(3)
  prefix.writeUInt8(0x01, 0)
  prefix.writeUInt8(0x42, 1)
  prefix.writeUInt8(flagByte, 2)

  return Buffer.concat([prefix, salt, cipherText])
}

Bip38.prototype.encrypt = function (wif, passphrase, saltAddress, progressCallback) {
  var d = cs.decode(wif).slice(1)
  var compressed = (d.length === 33) && (d[32] === 0x01)

  // truncate the compression flag
  if (compressed) {
    d = d.slice(0, -1)
  }

  return cs.encode(this.encryptRaw(d, compressed, passphrase, saltAddress, progressCallback))
}

// some of the techniques borrowed from: https://github.com/pointbiz/bitaddress.org
// todo: (optimization) init buffer in advance, and use copy instead of concat
Bip38.prototype.decryptRaw = function (encData, passphrase, progressCallback) {
  // 39 bytes: 2 bytes prefix, 37 bytes payload
  assert.equal(encData.length, 39, 'Invalid BIP38 data length')

  // first byte is always 0x01
  assert.equal(encData.readUInt8(0), 0x01, 'Invalid BIP38 prefix')

  // check if BIP38 EC multiply
  var type = encData.readUInt8(1)
  if (type === 0x43) {
    return this.decryptECMult(encData, passphrase)
  }

  passphrase = new Buffer(passphrase, 'utf8')

  assert.equal(type, 0x42, 'Invalid BIP38 type')
  var flagByte = encData.readUInt8(2)
  var compressed = flagByte === 0xe0

  if (!compressed) {
    assert.equal(flagByte, 0xc0, 'Invalid BIP38 compression flag')
  }

  var N = this.scryptParams.N
  var r = this.scryptParams.r
  var p = this.scryptParams.p

  var addresshash = encData.slice(3, 7)
  var scryptBuf = scrypt(passphrase, addresshash, N, r, p, 64, progressCallback)
  var derivedHalf1 = scryptBuf.slice(0, 32)
  var derivedHalf2 = scryptBuf.slice(32, 64)

  var privKeyBuf = encData.slice(7, 7 + 32)
  var decipher = aes.createDecipheriv('aes-256-ecb', derivedHalf2, new Buffer(0))
  decipher.setAutoPadding(false)
  decipher.end(privKeyBuf)

  var plainText = decipher.read()
  var privateKey = xor(plainText, derivedHalf1)

  return {
    privateKey: privateKey,
    compressed: compressed
  }
}

Bip38.prototype.decrypt = function (encryptedBase58, passphrase, progressCallback) {
  var encBuffer = cs.decode(encryptedBase58)
  var decrypt = this.decryptRaw(encBuffer, passphrase, progressCallback)

  // Convert to WIF
  var bufferLen = decrypt.compressed ? 34 : 33
  var buffer = new Buffer(bufferLen)

  buffer.writeUInt8(this.versions.private, 0)
  decrypt.privateKey.copy(buffer, 1)

  if (decrypt.compressed) {
    buffer.writeUInt8(0x01, 33)
  }

  return cs.encode(buffer)
}

Bip38.prototype.decryptECMult = function (encData, passphrase, progressCallback) {
  passphrase = new Buffer(passphrase, 'utf8')
  encData = encData.slice(1) // FIXME: we can avoid this

  var compressed = (encData[1] & 0x20) !== 0
  var hasLotSeq = (encData[1] & 0x04) !== 0

  assert.equal((encData[1] & 0x24), encData[1], 'Invalid private key.')

  var addresshash = encData.slice(2, 6)
  var ownerEntropy = encData.slice(6, 14)
  var ownerSalt

  // 4 bytes ownerSalt if 4 bytes lot/sequence
  if (hasLotSeq) {
    ownerSalt = ownerEntropy.slice(0, 4)

  // else, 8 bytes ownerSalt
  } else {
    ownerSalt = ownerEntropy
  }

  var encryptedPart1 = encData.slice(14, 22) // First 8 bytes
  var encryptedPart2 = encData.slice(22, 38) // 16 bytes

  var N = this.scryptParams.N
  var r = this.scryptParams.r
  var p = this.scryptParams.p
  var preFactor = scrypt(passphrase, ownerSalt, N, r, p, 32, progressCallback)

  var passFactor
  if (hasLotSeq) {
    var hashTarget = Buffer.concat([preFactor, ownerEntropy])
    passFactor = sha256x2(hashTarget)

  } else {
    passFactor = preFactor
  }

  var passInt = BigInteger.fromBuffer(passFactor)
  var passPoint = curve.G.multiply(passInt).getEncoded(true)

  var seedBPass = scrypt(passPoint, Buffer.concat([addresshash, ownerEntropy]), 1024, 1, 1, 64)
  var derivedHalf1 = seedBPass.slice(0, 32)
  var derivedHalf2 = seedBPass.slice(32, 64)

  var decipher = aes.createDecipheriv('aes-256-ecb', derivedHalf2, new Buffer(0))
  decipher.setAutoPadding(false)
  decipher.end(encryptedPart2)

  var decryptedPart2 = decipher.read()
  var tmp = xor(decryptedPart2, derivedHalf1.slice(16, 32))
  var seedBPart2 = tmp.slice(8, 16)

  var decipher2 = aes.createDecipheriv('aes-256-ecb', derivedHalf2, new Buffer(0))
  decipher2.setAutoPadding(false)
  decipher2.write(encryptedPart1) // first 8 bytes
  decipher2.end(tmp.slice(0, 8)) // last 8 bytes

  var seedBPart1 = xor(decipher2.read(), derivedHalf1.slice(0, 16))
  var seedB = Buffer.concat([seedBPart1, seedBPart2], 24)
  var factorB = sha256x2(seedB)

  // d = passFactor * factorB (mod n)
  var d = passInt.multiply(BigInteger.fromBuffer(factorB)).mod(curve.n)

  return {
    privateKey: d.toBuffer(32),
    compressed: compressed
  }
}

Bip38.prototype.verify = function (encryptedBase58) {
  var decoded
  try {
    decoded = cs.decode(encryptedBase58)
  } catch (e) {
    return false
  }

  if (decoded.length !== 39) return false
  if (decoded.readUInt8(0) !== 0x01) return false

  var type = decoded.readUInt8(1)
  var flag = decoded.readUInt8(2)

  // encrypted WIF
  if (type === 0x42) {
    if (flag !== 0xc0 && flag !== 0xe0) return false

  // EC mult
  } else if (type === 0x43) {
    if ((flag & ~0x24)) return false

  } else {
    return false
  }

  return true
}

module.exports = Bip38
