var crypto = require('crypto')
var AES = require('aes')
var scrypt = require('scryptsy')
var base58 = require('bs58')
var ecurve = require('ecurve')
var ecparams = ecurve.getCurveByName('secp256k1')
var BigInteger = require('bigi')

function Bip38() {
  if (!(this instanceof Bip38)) return new Bip38()

  //default to Bitcoin params
  this.addressVersion = {private: 0x80, public: 0x0}
  this.scryptParams = {N: 16384, r: 8, p: 8}; //BIP38 recommended
}

//Bitcoin only
Bip38.encrypt = function() {
  var b = new Bip38()
  return b.encrypt.apply(b, arguments)
}
//Bitcoin only
Bip38.decrypt = function() {
  var b = new Bip38()
  return b.decrypt.apply(b, arguments)
}


//todo: (optimization) init buffer in advance, and use copy instead of concat
Bip38.prototype.encrypt = function(wif, passphrase, address) {
  var N = this.scryptParams.N, r = this.scryptParams.r, p = this.scryptParams.p
  passphrase = new Buffer(passphrase, 'utf8')
  
  var wifBuf = base58.decode(wif)
  if (wifBuf[0] !== this.addressVersion.private) {
    throw new Error("Incompatible address settings. Did you forget to set addressVersion?")
  }

  var compressed = (wifBuf[wifBuf.length - 5] === 0x01)
  var privKeyBuf = wifBuf.slice(1, 33)
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

  var encryptedKey = Buffer.concat([prefix, salt, encryptedhalf1, encryptedhalf2])
  encryptedKey = Buffer.concat([encryptedKey, sha256x2(encryptedKey).slice(0, 4)])

  return base58.encode(encryptedKey)
}

//some of the techniques borrowed from: https://github.com/pointbiz/bitaddress.org
//todo: (optimization) init buffer in advance, and use copy instead of concat
Bip38.prototype.decrypt = function(encryptedKey, passphrase) {
  var N = this.scryptParams.N, r = this.scryptParams.r, p = this.scryptParams.p
  passphrase = new Buffer(passphrase, 'utf8')

  var hex = base58.decode(encryptedKey) //variable not really hex

  // 43 bytes: 2 bytes prefix, 37 bytes payload, 4 bytes checksum
  if (hex.length != 43) throw new Error("Invalid private key.")
      
  // first byte is always 0x01 
  if (hex[0] != 0x01) throw new Error("Invalid private key.")

  var expChecksum = hex.slice(-4)
  hex = hex.slice(0, -4)
  var checksum = sha256x2(hex).slice(0,4)

  if (checksum[0] != expChecksum[0] || checksum[1] != expChecksum[1] || checksum[2] != expChecksum[2] || checksum[3] != expChecksum[3]) {
    throw new Error("Invalid private key.")
  }

  var compressed = false
  var isECMult = false
  var hasLotSeq = false
  // second byte for non-EC-multiplied key
  if (hex[1] == 0x42) {
    if (hex[2] == 0xe0) // key should use compression 
      compressed = true
    else if (hex[2] != 0xc0) // key should NOT use compression
      throw new Error("Invalid private key.")
  }
  // second byte for EC-multiplied key 
  else if (hex[1] == 0x43) {
    isECMult = true
    compressed = (hex[2] & 0x20) != 0
    hasLotSeq = (hex[2] & 0x04) != 0
    if ((hex[2] & 0x24) != hex[2]) 
      throw new Error("Invalid private key.")
  }
  else {
    throw new Error("Invalid private key.")
  }

  var addresshash = hex.slice(3, 7)
  if (!isECMult) {
    var scryptBuf = scrypt(passphrase, addresshash, N, r, p, 64)
    var derivedHalf1 = scryptBuf.slice(0, 32)
    var derivedHalf2 = scryptBuf.slice(32, 64)

    var aes = createAES(derivedHalf2)
    var decryptFn = aes.decrypt.bind(aes)

    var privKeyBuf = hex.slice(7, 7 + 32)
    var decryptedhalf1 = callAES(privKeyBuf.slice(0, 16), decryptFn)
    var decryptedhalf2 = callAES(privKeyBuf.slice(16, 32), decryptFn)
    var dec = Buffer.concat([decryptedhalf1, decryptedhalf2])

    for (var x = 0; x < 32; x++) 
      dec[x] ^= scryptBuf[x]

    /*var checksumAddr = sha256.x2(address, {in: 'utf8', out: 'buffer'})
    if (checksumAddr[0] != hex[3] || checksumAddr[1] != hex[4] || checksumAddr[2] != hex[5] || checksumAddr[3] != hex[6]) {
      throw new Error("Incorrect passphrase.")
    }*/

    return privateKeyToWif.call(this, dec, compressed)
  } else {
    var ownerEntropy = hex.slice(7, 15)
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
    
    var encryptedPart1 = hex.slice(15, 23); // First 8 bytes
    var encryptedPart2 = hex.slice(23, 39); // 16 bytes
    
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
    
    var privKey = new BigInteger(passFactor.toString('hex'), 16).multiply(new BigInteger(factorB.toString('hex'), 16)).mod(ecparams.params.n)
    privKey = new Buffer(privKey.toString(16), 'hex'); // Convert from BigInteger to Buffer
    
    return privateKeyToWif.call(this, privKey, compressed)
  }
}

function printArr(arr) {
  console.log(arr.join(','))
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
  var versionBuffer = new Buffer(1); versionBuffer[0] = this.addressVersion.private
  var compressedBuffer = new Buffer(1); compressedBuffer[0] = 0x01

  //convert to wif
  if (!compressed) {
    var checksum = sha256x2(Buffer.concat([versionBuffer, privateKey])).slice(0,4)
    return base58.encode(Buffer.concat([versionBuffer, privateKey, checksum]))
  } else {
    var checksum = sha256x2(Buffer.concat([versionBuffer, privateKey, compressedBuffer])).slice(0,4)
    return base58.encode(Buffer.concat([versionBuffer, privateKey, compressedBuffer, checksum]))
  }
}

//convert 256 bit buffer to SJCL AES (requires big endian)
function createAES(keyBuffer) {
  if (keyBuffer.length != 32)
    throw new Error("AES key must be 256 bits.")
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



