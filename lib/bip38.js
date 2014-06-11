var crypto = require('crypto')
var assert = require('assert')
var AES = require('aes')
var scrypt = require('scryptsy')
var ecurve = require('ecurve')
var ecparams = ecurve.getCurveByName('secp256k1')
var BigInteger = require('bigi')
var cs = require('coinstring')

function Bip38(versions) {
  if (!(this instanceof Bip38)) return new Bip38()

  //default to Bitcoin params
  this.versions = versions || {private: 0x80, public: 0x0}
  this.scryptParams = {N: 16384, r: 8, p: 8}; //BIP38 recommended
}

//todo: (optimization) init buffer in advance, and use copy instead of concat
Bip38.prototype.encrypt = function(wif, passphrase, address) {
  var N = this.scryptParams.N, r = this.scryptParams.r, p = this.scryptParams.p
  passphrase = new Buffer(passphrase, 'utf8')

  var wifBuf = cs.decode(wif, this.versions.private).payload

  var compressed = (wifBuf[wifBuf.length - 1] === 0x01)
  var privKeyBuf = wifBuf.slice(0, 32)
  var salt = sha256x2(new Buffer(address, 'utf8')).slice(0, 4)

  var scryptBuf = scrypt(passphrase, salt, N, r, p, 64)
  var derivedHalf1 = scryptBuf.slice(0, 32)
  var derivedHalf2 = scryptBuf.slice(32, 64)

  var aes = createAES(derivedHalf2)
  for (var i = 0; i < 32; ++i) {
    privKeyBuf[i] ^= derivedHalf1[i]
  }

  var encryptFn = aes.encrypt.bind(aes)
  var encryptedhalf1 = callAES(privKeyBuf.slice(0, 16), encryptFn)
  var encryptedhalf2 = callAES(privKeyBuf.slice(16, 32), encryptFn)

  // 0x01 0x42 + flagByte + salt + encryptedhalf1 + encryptedhalf2
  var flagByte = compressed ? 0xe0 : 0xc0
  var prefix = new Buffer(3)
  prefix[0] = 0x01; prefix[1] = 0x42; prefix[2] = flagByte

  return cs.encode(Buffer.concat([salt, encryptedhalf1, encryptedhalf2]), new Buffer(prefix))
}

//some of the techniques borrowed from: https://github.com/pointbiz/bitaddress.org
//todo: (optimization) init buffer in advance, and use copy instead of concat
Bip38.prototype.decrypt = function(encryptedKey, passphrase) {
  var N = this.scryptParams.N, r = this.scryptParams.r, p = this.scryptParams.p
  passphrase = new Buffer(passphrase, 'utf8')

  var encData = cs.decode(encryptedKey)

  // 43 bytes: 2 bytes prefix, 37 bytes payload, 4 bytes checksum
  //if (hex.length != 43) throw new Error("Invalid private key.")
  assert.equal(encData.payload.length, 38, "Invalid private key")
      
  // first byte is always 0x01
  assert.equal(encData.version.toString('hex'), '01', 'Invalid private key')
  encData = encData.payload

  var compressed = false
  var isECMult = false
  var hasLotSeq = false
  // second byte for non-EC-multiplied key
  if (encData[0] == 0x42) {
    if (encData[1] == 0xe0) // key should use compression 
      compressed = true
    else // key should NOT use compression
      assert(encData[1], 0xc0, 'Invalid private key.')
  }
  // second byte for EC-multiplied key 
  else if (encData[0] == 0x43) {
    isECMult = true
    compressed = (encData[1] & 0x20) != 0
    hasLotSeq = (encData[1] & 0x04) != 0 
    assert.equal((encData[1] & 0x24), encData[1], "Invalid private key.")
  }
  else {
    throw new Error("Invalid private key.")
  }

  var addresshash = encData.slice(2, 6)
  if (!isECMult) {
    var scryptBuf = scrypt(passphrase, addresshash, N, r, p, 64)
    var derivedHalf1 = scryptBuf.slice(0, 32)
    var derivedHalf2 = scryptBuf.slice(32, 64)

    var aes = createAES(derivedHalf2)
    var decryptFn = aes.decrypt.bind(aes)

    var privKeyBuf = encData.slice(6, 6 + 32)
    var decryptedhalf1 = callAES(privKeyBuf.slice(0, 16), decryptFn)
    var decryptedhalf2 = callAES(privKeyBuf.slice(16, 32), decryptFn)
    var dec = Buffer.concat([decryptedhalf1, decryptedhalf2])

    for (var x = 0; x < 32; x++) 
      dec[x] ^= scryptBuf[x]

    return privateKeyToWif.call(this, dec, compressed)
  } else {
    var ownerEntropy = encData.slice(6, 14)
    if (hasLotSeq) {
      // four bytes ownerSalt, four bytes lot/sequence
      var ownerSalt = ownerEntropy.slice(0, 4)
      var lotSeq = ownerEntropy.readInt32BE(4)
      var sequenceNumber = lotSeq & 0xFFF
      var lotNumber = (lotSeq >> 12) & 0xFFFFF
    } else {
      // eight bytes ownerSalt
      var ownerSalt = ownerEntropy
    }
    
    var encryptedPart1 = encData.slice(14, 22); // First 8 bytes
    var encryptedPart2 = encData.slice(22, 38); // 16 bytes
    
    var preFactor = scrypt(passphrase, ownerSalt, N, r, p, 32)
    if (hasLotSeq) {
      var hashTarget = Buffer.concat([preFactor, ownerEntropy])
      var passFactor = sha256x2(hashTarget)
    } else {
      var passFactor = preFactor
    }
    var passPoint = new Buffer(ecparams.params.G.multiply(new BigInteger(passFactor.toString('hex'), 16)).getEncoded(true))
    
    var seedBPass = scrypt(passPoint, Buffer.concat([addresshash, ownerEntropy]), 1024, 1, 1, 64)
    var derivedHalf1 = seedBPass.slice(0,32)
    var derivedHalf2 = seedBPass.slice(32,64)
    
    var aes = createAES(derivedHalf2)
    var decryptFn = aes.decrypt.bind(aes)
    
    var tmp = BufferXOR(callAES(encryptedPart2, decryptFn), derivedHalf1.slice(16,32))
    encryptedPart1 = Buffer.concat([encryptedPart1, tmp.slice(0,8)], 16); // Append last 8 bytes
    var seedBPart2 = tmp.slice(8, 16)
    var tmp2 = callAES(encryptedPart1, decryptFn)
    var seedBPart1 = BufferXOR(tmp2, derivedHalf1.slice(0,16))
    var seedB = Buffer.concat([seedBPart1, seedBPart2], 24)
    var factorB = sha256x2(seedB)
    
    var privKey = BigInteger.fromBuffer(passFactor)
                            .multiply(BigInteger.fromBuffer(factorB))
                            .mod(ecparams.params.n)
                            .toBuffer()
    
    return privateKeyToWif.call(this, privKey, compressed)
  }
}

function BufferXOR(buf1, buf2) {
  if (buf1.length != buf2.length) return false
  var out = new Buffer(buf1.length)
  for (var i = 0; i < buf1.length; i++) {
    out[i] = buf1[i] ^ buf2[i]
  }
  return out
}

function privateKeyToWif(privateKey, compressed) {
  var versionBuffer = new Buffer(1); versionBuffer[0] = this.versions.private
  var compressedBuffer = new Buffer(1); compressedBuffer[0] = 0x01

  //convert to wif
  if (!compressed) 
    return cs.encode(privateKey, versionBuffer)
  else
    return cs.encode(Buffer.concat([privateKey, compressedBuffer]), versionBuffer)
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
    part.push(dataBuffer.readUInt32BE(i*4))
  }

  var encryptedData = fn(part)
  var encryptedDataBuf = new Buffer(16)
  for (var i = 0; i < encryptedData.length; ++i) {
    encryptedDataBuf.writeUInt32BE(encryptedData[i], i*4)
  }
  return encryptedDataBuf
}

function sha256x2(input) {
  var hash = crypto.createHash('sha256').update(input).digest()
  return crypto.createHash('sha256').update(hash).digest()
}

module.exports = Bip38



