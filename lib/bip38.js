var AES = require('aes');
var scrypt = require('scryptsy').scrypt;
var sha256 = require('crypto-hashing').sha256;
var conv = require('binstring')
var Address = require('btc-address')
var ECKey = require('eckey');
var base58 = require('bs58');

module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;

function ERR(code, msg) {
  var e = new Error(msg);
  e.code = code;
  throw e;
}

var getBitcoinPrivateKeyByteArray = function () {
    // Get a copy of private key as a byte array
    var bytes = this.priv.toByteArrayUnsigned();
    // zero pad if private key is less than 32 bytes 
    while (bytes.length < 32) bytes.unshift(0x00);
    return bytes;
};


function encrypt(key, passphrase) {
  //var data = conv(key);
  var privKey = new ECKey(key);
  var compressed = false;
  var privKeyBytes = getBitcoinPrivateKeyByteArray.call(privKey);
  privKey.setCompressed = true;
  var address = privKey.getBitcoinAddress().toString();

  var salt = sha256.x2(address, {in: 'utf8', out: 'bytes'}).slice(0, 4);

  // derive key using scrypt
  //var AES_opts = { mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true };

  var scryptBuf = scrypt(passphrase, new Buffer(salt), 16384, 8, 8, 64);
  var derivedHalf1 = scryptBuf.slice(0, 32);
  var derivedHalf2 = scryptBuf.slice(32, 64);

  var aesKey = [];
  for (var i = 0; i < 8; ++i) {
    aesKey.push(derivedHalf2.readUInt32BE(i*4));
  }
  var aes = new AES(aesKey);

  for (var i = 0; i < 32; ++i) {
    privKeyBytes[i] ^= derivedHalf1[i];
  }

  var privKeyBuf = new Buffer(privKeyBytes);

  var part1 = [];
  var buf1 = privKeyBuf.slice(0, 16);
  for (var i = 0; i < 4; ++i) {
    part1.push(buf1.readUInt32BE(i*4));
  }

  var part2 = [];
  var buf2 = privKeyBuf.slice(16, 32);
  for (var i = 0; i < 4; ++i) {
    part2.push(buf2.readUInt32BE(i*4));
  }

  var encryptedhalf1 = aes.encrypt(part1);
  var encryptedhalfBuf1 = new Buffer(16);
  for (var i = 0; i < encryptedhalf1.length; ++i) {
    encryptedhalfBuf1.writeUInt32BE(encryptedhalf1[i], i*4);
  }

  var encryptedhalf2 = aes.encrypt(part2);
  var encryptedhalfBuf2 = new Buffer(16);
  for (var i = 0; i < encryptedhalf2.length; ++i) {
    encryptedhalfBuf2.writeUInt32BE(encryptedhalf2[i], i*4);
  }

  encryptedhalf1 = Array.prototype.slice.call(encryptedhalfBuf1, 0);
  encryptedhalf2 = Array.prototype.slice.call(encryptedhalfBuf2, 0);

  var enc = []
  enc = enc.concat(encryptedhalf1);
  enc = enc.concat(encryptedhalf2);


  // 0x01 0x42 + flagbyte + salt + encryptedhalf1 + encryptedhalf2
  var flagByte = compressed ? 0xe0 : 0xc0;
  var encryptedKey = [0x01, 0x42, flagByte].concat(salt);
      
  encryptedKey = encryptedKey.concat(enc);
  encryptedKey = encryptedKey.concat(sha256.x2(encryptedKey, {in: 'bytes', out: 'bytes'}).slice(0, 4));

  return base58.encode(encryptedKey);
}

function decrypt() {
  
}

