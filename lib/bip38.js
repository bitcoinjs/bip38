var AES = require('aes')
var assert = require('assert')
var crypto = require('crypto')
var cs = require('coinstring')
var scrypt = require('scryptsy')

var ecurve = require('ecurve')
var curve = ecurve.getCurveByName('secp256k1')

var BigInteger = require('bigi')

function Bip38(versions) {
  if (!(this instanceof Bip38)) return new Bip38()

  // default to Bitcoin WIF versions
  this.versions = versions || {
    private: 0x80,
    public: 0x0
  }

  // BIP38 recommended
  this.scryptParams = {
    N: 16384,
    r: 8,
    p: 8
  }
}

Bip38.prototype.encryptRaw = function(buffer, compressed, passphrase, saltAddress) {
  assert.equal(buffer.length, 32, 'Invalid private key length')

  var secret = new Buffer(passphrase, 'utf8')
  var salt = sha256x2(saltAddress).slice(0, 4)

  var N = this.scryptParams.N
  var r = this.scryptParams.r
  var p = this.scryptParams.p

  var scryptBuf = scrypt(secret, salt, N, r, p, 64)
  var derivedHalf1 = scryptBuf.slice(0, 32)
  var derivedHalf2 = scryptBuf.slice(32, 64)

  var aes = createAES(derivedHalf2)
  var encryptFn = aes.encrypt.bind(aes)

  var xorBuf = BufferXOR(buffer, derivedHalf1)
  var encryptedHalf1 = callAES(xorBuf.slice(0, 16), encryptFn)
  var encryptedHalf2 = callAES(xorBuf.slice(16, 32), encryptFn)

  // 0x01 + 0x42 + flagByte + salt + encryptedHalf1 + encryptedHalf2
  var flagByte = compressed ? 0xe0 : 0xc0
  var prefix = new Buffer(3)
  prefix.writeUInt8(0x01, 0)
  prefix.writeUInt8(0x42, 1)
  prefix.writeUInt8(flagByte, 2)

  return Buffer.concat([prefix, salt, encryptedHalf1, encryptedHalf2])
}

Bip38.prototype.encrypt = function(wif, passphrase, saltAddress) {
  var d = cs.decode(wif).slice(1)
  var compressed = (d.length === 33) && (d[32] === 0x01)

  // truncate the compression flag
  if (compressed) {
    d = d.slice(0, -1)
  }

  return cs.encode(this.encryptRaw(d, compressed, passphrase, saltAddress))
}

//some of the techniques borrowed from: https://github.com/pointbiz/bitaddress.org
//todo: (optimization) init buffer in advance, and use copy instead of concat
Bip38.prototype.decryptRaw = function(encData, passphrase) {
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
  var scryptBuf = scrypt(passphrase, addresshash, N, r, p, 64)
  var derivedHalf1 = scryptBuf.slice(0, 32)
  var derivedHalf2 = scryptBuf.slice(32, 64)

  var aes = createAES(derivedHalf2)
  var decryptFn = aes.decrypt.bind(aes)

  var privKeyBuf = encData.slice(7, 7 + 32)
  var decryptedHalf1 = callAES(privKeyBuf.slice(0, 16), decryptFn)
  var decryptedHalf2 = callAES(privKeyBuf.slice(16, 32), decryptFn)
  var dec = Buffer.concat([decryptedHalf1, decryptedHalf2])

  for (var x = 0; x < 32; x++) {
    dec[x] ^= derivedHalf1[x]
  }

  return {
    privateKey: dec,
    compressed: compressed
  }
}

Bip38.prototype.decrypt = function(encryptedBase58, passphrase) {
  var encBuffer = cs.decode(encryptedBase58)
  var decrypt = this.decryptRaw(encBuffer, passphrase)

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

Bip38.prototype.decryptECMult = function(encData, passphrase) {
  passphrase = new Buffer(passphrase, 'utf8')
  encData = encData.slice(1) // FIXME: we can avoid this

  var compressed = (encData[1] & 0x20) !== 0
  var hasLotSeq = (encData[1] & 0x04) !== 0

  assert.equal((encData[1] & 0x24), encData[1], "Invalid private key.")

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
  var preFactor = scrypt(passphrase, ownerSalt, N, r, p, 32)

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
  var derivedHalf1 = seedBPass.slice(0,32)
  var derivedHalf2 = seedBPass.slice(32,64)

  var aes = createAES(derivedHalf2)
  var decryptFn = aes.decrypt.bind(aes)

  var tmp = BufferXOR(callAES(encryptedPart2, decryptFn), derivedHalf1.slice(16,32))
  encryptedPart1 = Buffer.concat([encryptedPart1, tmp.slice(0, 8)], 16); // Append last 8 bytes

  var seedBPart2 = tmp.slice(8, 16)
  var tmp2 = callAES(encryptedPart1, decryptFn)
  var seedBPart1 = BufferXOR(tmp2, derivedHalf1.slice(0,16))
  var seedB = Buffer.concat([seedBPart1, seedBPart2], 24)
  var factorB = sha256x2(seedB)

  // d = passFactor * factorB (mod n)
  var d = passInt.multiply(BigInteger.fromBuffer(factorB)).mod(curve.n)

  return {
    privateKey: d.toBuffer(32),
    compressed: compressed
  }
}

function BufferXOR(buf1, buf2) {
  assert.equal(buf1.length, buf2.length)

  var out = new Buffer(buf1.length)
  for (var i = 0; i < buf1.length; i++) {
    out[i] = buf1[i] ^ buf2[i]
  }

  return out
}

//convert 256 bit buffer to SJCL AES (requires big endian)
function createAES(keyBuffer) {
  assert.equal(keyBuffer.length, 32, 'AES key must be 256 bits')

  var aesKey = []

  for (var i = 0; i < 8; ++i) {
    aesKey.push(keyBuffer.readUInt32BE(i*4))
  }

  return new AES(aesKey)
}

function callAES(dataBuffer, fn) {
  var part = []
  for (var i = 0; i < 4; ++i) {
    part.push(dataBuffer.readUInt32BE(i * 4))
  }

  var encryptedData = fn(part)
  var encryptedDataBuf = new Buffer(16)

  for (var i = 0; i < encryptedData.length; ++i) {
    encryptedDataBuf.writeUInt32BE(encryptedData[i], i * 4)
  }

  return encryptedDataBuf
}

// SHA256(SHA256(buffer))
function sha256x2(buffer) {
  buffer = crypto.createHash('sha256').update(buffer).digest()
  return crypto.createHash('sha256').update(buffer).digest()
}

module.exports = Bip38
