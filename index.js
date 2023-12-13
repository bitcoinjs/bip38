var aes = require('@noble/ciphers/aes');
var { scrypt, scryptAsync } = require('@noble/hashes/scrypt');
var { secp256k1 } = require('@noble/curves/secp256k1');
var { sha256 } = require('@noble/hashes/sha256');
var { ripemd160 } = require('@noble/hashes/ripemd160');
var { createBase58check } = require('@scure/base');
var bs58check = createBase58check(sha256);

function xor(a, b) {
  var length = Math.min(a.length, b.length);

  for (var i = 0; i < length; ++i) {
    a[i] = a[i] ^ b[i];
  }

  return a;
}

// constants
var SCRYPT_PARAMS = {
  N: 16384, // specified by BIP38
  r: 8,
  p: 8,
};

function hash160(buffer) {
  return Buffer.from(ripemd160(sha256(buffer)));
}

function hash256(buffer) {
  return Buffer.from(sha256(sha256(buffer)));
}

function getAddress(d, compressed) {
  const dBigInt = BigInt('0x' + d.toString(16));
  const Q = secp256k1.getPublicKey(dBigInt);
  const hash = hash160(Q);
  const payload = Buffer.allocUnsafe(21);
  payload.writeUInt8(0x00, 0); // Bitcoin version byte
  hash.copy(payload, 1);

  return bs58check.encode(payload);
}

function prepareEncryptRaw(buffer, compressed, passphrase, scryptParams) {
  if (buffer.length !== 32) throw new Error('Invalid private key length');

  var d = BigInt('0x' + buffer.toString('hex'));
  var address = getAddress(d, compressed);
  var secret = Buffer.from(passphrase.normalize('NFC'), 'utf8');
  var salt = hash256(address).slice(0, 4);

  var N = scryptParams.N;
  var r = scryptParams.r;
  var p = scryptParams.p;

  return {
    secret,
    salt,
    N,
    r,
    p,
  };
}

function finishEncryptRaw(buffer, compressed, salt, scryptBuf) {
  var derivedHalf1 = scryptBuf.slice(0, 32);
  var derivedHalf2 = scryptBuf.slice(32, 64);

  var xorBuf = xor(derivedHalf1, buffer);

  var stream = aes.ecb(derivedHalf2, { disablePadding: true });
  var cipherText = stream.encrypt(xorBuf);

  // 0x01 | 0x42 | flagByte | salt (4) | cipherText (32)
  var result = Buffer.allocUnsafe(7 + cipherText.length);
  result.writeUInt8(0x01, 0);
  result.writeUInt8(0x42, 1);
  result.writeUInt8(compressed ? 0xe0 : 0xc0, 2);
  salt.copy(result, 3);
  Buffer.from(cipherText).copy(result, 7);

  return result;
}

async function encryptRawAsync(buffer, compressed, passphrase, onProgress, scryptParams) {
  scryptParams = scryptParams || SCRYPT_PARAMS;
  const { secret, salt, N, r, p } = prepareEncryptRaw(buffer, compressed, passphrase, scryptParams);

  var scryptBuf = Buffer.from(await scryptAsync(secret, salt, { N, r, p, dkLen: 64, onProgress }));

  return finishEncryptRaw(buffer, compressed, salt, scryptBuf);
}

function encryptRaw(buffer, compressed, passphrase, onProgress, scryptParams) {
  scryptParams = scryptParams || SCRYPT_PARAMS;
  const { secret, salt, N, r, p } = prepareEncryptRaw(buffer, compressed, passphrase, scryptParams);

  var scryptBuf = scrypt(secret, salt, { N, r, p, dkLen: 64, onProgress });

  return finishEncryptRaw(buffer, compressed, salt, scryptBuf);
}

async function encryptAsync(buffer, compressed, passphrase, onProgress, scryptParams) {
  return bs58check.encode(
    await encryptRawAsync(buffer, compressed, passphrase, onProgress, scryptParams)
  );
}

function encrypt(buffer, compressed, passphrase, onProgress, scryptParams) {
  return bs58check.encode(encryptRaw(buffer, compressed, passphrase, onProgress, scryptParams));
}

function prepareDecryptRaw(buffer, onProgress, scryptParams) {
  buffer = Buffer.from(buffer);

  // 39 bytes: 2 bytes prefix, 37 bytes payload
  if (buffer.length !== 39) throw new Error('Invalid BIP38 data length');
  if (buffer.readUInt8(0) !== 0x01) throw new Error('Invalid BIP38 prefix');

  // check if BIP38 EC multiply
  var type = buffer.readUInt8(1);
  if (type === 0x43) return { decryptEC: true };
  if (type !== 0x42) throw new Error('Invalid BIP38 type');

  var flagByte = buffer.readUInt8(2);
  var compressed = flagByte === 0xe0;
  if (!compressed && flagByte !== 0xc0) throw new Error('Invalid BIP38 compression flag');

  var N = scryptParams.N;
  var r = scryptParams.r;
  var p = scryptParams.p;

  var salt = buffer.slice(3, 7);
  return {
    salt,
    compressed,
    N,
    r,
    p,
  };
}

function finishDecryptRaw(buffer, salt, compressed, scryptBuf) {
  var derivedHalf1 = scryptBuf.slice(0, 32);
  var derivedHalf2 = scryptBuf.slice(32, 64);

  var privKeyBuf = Buffer.from(buffer.slice(7, 7 + 32));
  var stream = aes.ecb(derivedHalf2, { disablePadding: true });
  var plainText = stream.decrypt(privKeyBuf);

  var privateKey = xor(derivedHalf1, plainText);

  // verify salt matches address
  var d = BigInt('0x' + privateKey.toString(16));
  var address = getAddress(d, compressed);
  var checksum = hash256(address).slice(0, 4);
  if (Buffer.compare(salt, checksum)) throw new Error('Invalid checksum');

  return {
    privateKey: privateKey,
    compressed: compressed,
  };
}

async function decryptRawAsync(buffer, passphrase, onProgress, scryptParams) {
  scryptParams = scryptParams || SCRYPT_PARAMS;
  const { salt, compressed, N, r, p, decryptEC } = prepareDecryptRaw(
    buffer,
    onProgress,
    scryptParams
  );
  if (decryptEC === true) return decryptECMultAsync(buffer, passphrase, onProgress, scryptParams);

  var scryptBuf = await scryptAsync(passphrase.normalize('NFC'), salt, {
    N,
    r,
    p,
    dkLen: 64,
    onProgress,
  });
  return finishDecryptRaw(buffer, salt, compressed, scryptBuf);
}

// some of the techniques borrowed from: https://github.com/pointbiz/bitaddress.org
function decryptRaw(buffer, passphrase, onProgress, scryptParams) {
  Buffer.from(buffer);
  scryptParams = scryptParams || SCRYPT_PARAMS;
  const { salt, compressed, N, r, p, decryptEC } = prepareDecryptRaw(
    buffer,
    onProgress,
    scryptParams
  );
  if (decryptEC === true) return decryptECMult(buffer, passphrase, onProgress, scryptParams);
  var scryptBuf = scrypt(passphrase.normalize('NFC'), salt, {
    N,
    r,
    p,
    dkLen: 64,
    onProgress,
  });
  return finishDecryptRaw(buffer, salt, compressed, scryptBuf);
}

async function decryptAsync(string, passphrase, onProgress, scryptParams) {
  return decryptRawAsync(bs58check.decode(string), passphrase, onProgress, scryptParams);
}

function decrypt(string, passphrase, onProgress, scryptParams) {
  return decryptRaw(bs58check.decode(string), passphrase, onProgress, scryptParams);
}

function prepareDecryptECMult(buffer, passphrase, onProgress, scryptParams) {
  var flag = buffer.readUInt8(1);
  var compressed = (flag & 0x20) !== 0;
  var hasLotSeq = (flag & 0x04) !== 0;

  if ((flag & 0x24) !== flag) throw new Error('Invalid private key.');

  var addressHash = buffer.slice(2, 6);
  var ownerEntropy = buffer.slice(6, 14);
  var ownerSalt;

  // 4 bytes ownerSalt if 4 bytes lot/sequence
  if (hasLotSeq) {
    ownerSalt = ownerEntropy.slice(0, 4);

    // else, 8 bytes ownerSalt
  } else {
    ownerSalt = ownerEntropy;
  }

  var encryptedPart1 = buffer.slice(14, 22); // First 8 bytes
  var encryptedPart2 = buffer.slice(22, 38); // 16 bytes

  var N = scryptParams.N;
  var r = scryptParams.r;
  var p = scryptParams.p;
  return {
    addressHash,
    encryptedPart1,
    encryptedPart2,
    ownerEntropy,
    ownerSalt,
    hasLotSeq,
    compressed,
    N,
    r,
    p,
  };
}

function getPassIntAndPoint(preFactor, ownerEntropy, hasLotSeq) {
  var passFactor;
  if (hasLotSeq) {
    var hashTarget = Buffer.concat([preFactor, ownerEntropy]);
    passFactor = hash256(hashTarget);
  } else {
    passFactor = preFactor;
  }
  const passInt = BigInt('0x' + passFactor.toString('hex'));
  return {
    passInt,
    passPoint: secp256k1.Point.fromPrivateKey(passInt).toRawBytes(true),
  };
}

function finishDecryptECMult(seedBPass, encryptedPart1, encryptedPart2, passInt, compressed) {
  var derivedHalf1 = seedBPass.slice(0, 32);
  var derivedHalf2 = seedBPass.slice(32, 64);

  var stream = aes.ecb(derivedHalf2, { disablePadding: true });

  var decryptedPart2 = stream.decrypt(encryptedPart2);
  var tmp = xor(decryptedPart2, derivedHalf1.slice(16, 32));
  var seedBPart2 = tmp.slice(8, 16);

  // Reusing the stream for the second part of decryption
  var seedBPart1 = xor(
    stream.decrypt(Buffer.concat([encryptedPart1, tmp.slice(0, 8)])),
    derivedHalf1.slice(0, 16)
  );
  var seedB = Buffer.concat([seedBPart1, seedBPart2], 24);
  var factorB = BigInt('0x' + hash256(seedB).toString('hex'));

  // d = passFactor * factorB (mod n)
  var d = passInt.multiply(factorB).mod(secp256k1.CURVE.n);

  return {
    privateKey: d.toBuffer(32),
    compressed: compressed,
  };
}

async function decryptECMultAsync(buffer, passphrase, onProgress, scryptParams) {
  buffer = buffer.slice(1); // FIXME: we can avoid this
  passphrase = Buffer.from(passphrase.normalize('NFC'), 'utf8');
  scryptParams = scryptParams || SCRYPT_PARAMS;
  const {
    addressHash,
    encryptedPart1,
    encryptedPart2,
    ownerEntropy,
    ownerSalt,
    hasLotSeq,
    compressed,
    N,
    r,
    p,
  } = prepareDecryptECMult(buffer, passphrase, onProgress, scryptParams);

  var preFactor = await scryptAsync(passphrase, ownerSalt, {
    N,
    r,
    p,
    dkLen: 32,
    onProgress,
  });

  const { passInt, passPoint } = getPassIntAndPoint(preFactor, ownerEntropy, hasLotSeq);

  var seedBPass = await scryptAsync(passPoint, Buffer.concat([addressHash, ownerEntropy]), {
    N: 1024,
    r: 1,
    p: 1,
    dkLen: 64,
  });

  return finishDecryptECMult(seedBPass, encryptedPart1, encryptedPart2, passInt, compressed);
}

function decryptECMult(buffer, passphrase, onProgress, scryptParams) {
  buffer = buffer.slice(1); // FIXME: we can avoid this
  passphrase = Buffer.from(passphrase.normalize('NFC'), 'utf8');
  scryptParams = scryptParams || SCRYPT_PARAMS;
  const {
    addressHash,
    encryptedPart1,
    encryptedPart2,
    ownerEntropy,
    ownerSalt,
    hasLotSeq,
    compressed,
    N,
    r,
    p,
  } = prepareDecryptECMult(buffer, passphrase, onProgress, scryptParams);
  var preFactor = scrypt(passphrase, ownerSalt, {
    N,
    r,
    p,
    dkLen: 32,
    onProgress,
  });

  const { passInt, passPoint } = getPassIntAndPoint(preFactor, ownerEntropy, hasLotSeq);

  var seedBPass = scrypt(passPoint, Buffer.concat([addressHash, ownerEntropy]), {
    N: 1024,
    r: 1,
    p: 1,
    dkLen: 64,
  });

  return finishDecryptECMult(seedBPass, encryptedPart1, encryptedPart2, passInt, compressed);
}

function verify(string) {
  var decoded = bs58check.decode(string);
  if (!decoded) return false;

  if (decoded.length !== 39) return false;
  if (decoded.readUInt8(0) !== 0x01) return false;

  var type = decoded.readUInt8(1);
  var flag = decoded.readUInt8(2);

  // encrypted WIF
  if (type === 0x42) {
    if (flag !== 0xc0 && flag !== 0xe0) return false;

    // EC mult
  } else if (type === 0x43) {
    if (flag & ~0x24) return false;
  } else {
    return false;
  }

  return true;
}

module.exports = {
  decrypt: decrypt,
  decryptECMult: decryptECMult,
  decryptRaw: decryptRaw,
  encrypt: encrypt,
  encryptRaw: encryptRaw,
  decryptAsync: decryptAsync,
  decryptECMultAsync: decryptECMultAsync,
  decryptRawAsync: decryptRawAsync,
  encryptAsync: encryptAsync,
  encryptRawAsync: encryptRawAsync,
  verify: verify,
};
