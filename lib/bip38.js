//https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

var AES = require('aes');
var scrypt = require('scryptsy').scrypt;
var sha256 = require('crypto-hashing').sha256;
var base58 = require('bs58');

module.exports = Bip38;

function Bip38() {
  //default to Bitcoin params
  this.addressVersion = {private: 0x80, public: 0x0};
  this.scryptParams = {N: 16384, r: 8, p: 8}; //BIP38 recommended
}

//Bitcoin only
Bip38.encrypt = function() {
  var b = new Bip38();
  return b.encrypt.apply(b, arguments);
}
//Bitcoin only
Bip38.decrypt = function() {
  var b = new Bip38();
  return b.decrypt.apply(b, arguments);
}


//todo: (optimization) init buffer in advance, and use copy instead of concat
Bip38.prototype.encrypt = function(wif, passphrase, address) {
  var N = this.scryptParams.N, r = this.scryptParams.r, p = this.scryptParams.p;

  var wifBuf = base58.decode(wif);
  if (wifBuf[0] !== this.addressVersion.private) {
    throw new Error("Incompatible address settings. Did you forget to set addressVersion?")
  }

  var compressed = (wifBuf[wifBuf.length - 5] === 0x01);
  var privKeyBuf = wifBuf.slice(1, 33);
  var salt = sha256.x2(address, {in: 'utf8', out: 'buffer'}).slice(0, 4);

  var scryptBuf = scrypt(passphrase, salt, N, r, p, 64);
  var derivedHalf1 = scryptBuf.slice(0, 32);
  var derivedHalf2 = scryptBuf.slice(32, 64);

  var aes = createAES(derivedHalf2);
  for (var i = 0; i < 32; ++i) {
    privKeyBuf[i] ^= derivedHalf1[i];
  }

  var encryptFn = aes.encrypt.bind(aes);
  var encryptedhalf1 = callAES(privKeyBuf.slice(0, 16), encryptFn);
  var encryptedhalf2 = callAES(privKeyBuf.slice(16, 32), encryptFn);

  // 0x01 0x42 + flagByte + salt + encryptedhalf1 + encryptedhalf2
  var flagByte = compressed ? 0xe0 : 0xc0;
  var prefix = new Buffer(3);
  prefix[0] = 0x01; prefix[1] = 0x42; prefix[2] = flagByte;

  var encryptedKey = Buffer.concat([prefix, salt, encryptedhalf1, encryptedhalf2]);
  encryptedKey = Buffer.concat([encryptedKey, sha256.x2(encryptedKey, {in: 'buffer', out: 'buffer'}).slice(0, 4)]);

  return base58.encode(encryptedKey);
}

//some of the techniques borrowed from: https://github.com/pointbiz/bitaddress.org
//todo: (optimization) init buffer in advance, and use copy instead of concat
Bip38.prototype.decrypt = function(encryptedKey, passphrase) {
  var N = this.scryptParams.N, r = this.scryptParams.r, p = this.scryptParams.p;

  var hex = base58.decode(encryptedKey);

  // 43 bytes: 2 bytes prefix, 37 bytes payload, 4 bytes checksum
  if (hex.length != 43) throw new Error("Invalid private key.");
      
  // first byte is always 0x01 
  if (hex[0] != 0x01) throw new Error("Invalid private key.");

  var expChecksum = hex.slice(-4);
  hex = hex.slice(0, -4);
  var checksum = sha256.x2(hex, {in: 'buffer', out: 'buffer'}).slice(0,4);

  if (checksum[0] != expChecksum[0] || checksum[1] != expChecksum[1] || checksum[2] != expChecksum[2] || checksum[3] != expChecksum[3]) {
    throw new Error("Invalid private key.");
  }

  var compressed = false;
  var isECMult = false;
  var hasLotSeq = false;
  // second byte for non-EC-multiplied key
  if (hex[1] == 0x42) {
    if (hex[2] == 0xe0) // key should use compression 
      compressed = true;
    else if (hex[2] != 0xc0) // key should NOT use compression
      throw new Error("Invalid private key.");
  }
  // second byte for EC-multiplied key 
  else if (hex[1] == 0x43) {
    isECMult = true;
    compressed = (hex[2] & 0x20) != 0;
    hasLotSeq = (hex[2] & 0x04) != 0;
    if ((hex[2] & 0x24) != hex[2]) 
      throw new Error("Invalid private key.");
  }
  else {
    throw new Error("Invalid private key.");
  }

  if (!isECMult) {
    var addresshash = hex.slice(3, 7);
    var scryptBuf = scrypt(passphrase, addresshash, N, r, p, 64);
    var derivedHalf1 = scryptBuf.slice(0, 32);
    var derivedHalf2 = scryptBuf.slice(32, 64);

    var aes = createAES(derivedHalf2);
    var decryptFn = aes.decrypt.bind(aes);

    var privKeyBuf = hex.slice(7, 7 + 32);
    var decryptedhalf1 = callAES(privKeyBuf.slice(0, 16), decryptFn);
    var decryptedhalf2 = callAES(privKeyBuf.slice(16, 32), decryptFn);
    var dec = Buffer.concat([decryptedhalf1, decryptedhalf2]);

    for (var x = 0; x < 32; x++) 
      dec[x] ^= scryptBuf[x];

    /*var checksumAddr = sha256.x2(address, {in: 'utf8', out: 'buffer'});
    if (checksumAddr[0] != hex[3] || checksumAddr[1] != hex[4] || checksumAddr[2] != hex[5] || checksumAddr[3] != hex[6]) {
      throw new Error("Incorrect passphrase.");
    }*/

    return privateKeyToWif.call(this, dec, compressed);
  } else {
    throw new Error('Does not support EC Multiplied keys yet.')
  }
}

function printArr(arr) {
  console.log(arr.join(','))
}

function privateKeyToWif(privateKey, compressed) {
  var versionBuffer = new Buffer(1); versionBuffer[0] = this.addressVersion.private;
  var compressedBuffer = new Buffer(1); compressedBuffer[0] = 0x01;

  //convert to wif
  if (!compressed) {
    var checksum = sha256.x2(Buffer.concat([versionBuffer, privateKey]), {in: 'buffer', out: 'buffer'}).slice(0,4);
    return base58.encode(Buffer.concat([versionBuffer, privateKey, checksum]));
  } else {
    var checksum = sha256.x2(Buffer.concat([versionBuffer, privateKey, compressedBuffer]), {in: 'buffer', out: 'buffer'}).slice(0,4);
    return base58.encode(Buffer.concat([versionBuffer, privateKey, compressedBuffer, checksum]));
  }
}

//convert 256 bit buffer to SJCL AES (requires big endian)
function createAES(keyBuffer) {
  if (keyBuffer.length != 32)
    throw new Error("AES key must be 256 bits.")
  var aesKey = [];
  for (var i = 0; i < 8; ++i) {
    aesKey.push(keyBuffer.readUInt32BE(i*4));
  }
  return new AES(aesKey);
}

function callAES(dataBuffer, fn) {
  var part = [];
  for (var i = 0; i < 4; ++i) {
    part.push(dataBuffer.readUInt32BE(i*4));
  }

  var encryptedData = fn(part);
  var encryptedDataBuf = new Buffer(16);
  for (var i = 0; i < encryptedData.length; ++i) {
    encryptedDataBuf.writeUInt32BE(encryptedData[i], i*4);
  }
  return encryptedDataBuf;
}



