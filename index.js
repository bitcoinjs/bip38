let aes = require('@noble/ciphers/aes');
let { scrypt, scryptAsync } = require('@noble/hashes/scrypt');
let { secp256k1 } = require('@noble/curves/secp256k1');
let { sha256 } = require('@noble/hashes/sha256');
let { ripemd160 } = require('@noble/hashes/ripemd160');
let { createBase58check } = require('@scure/base');
let { bytesToNumberBE, numberToBytesBE } = require('@noble/curves/abstract/utils');
let { mod } = require('@noble/curves/abstract/modular');

let bs58check = createBase58check(sha256);

// constants
let SCRYPT_PARAMS = {
  N: 16384, // specified by BIP38
  r: 8,
  p: 8,
};

function equal(a, b) {
  if (a.length !== b.length) return false;

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }

  return true;
}

function xor(a, b) {
  let length = Math.min(a.length, b.length);

  for (let i = 0; i < length; ++i) {
    a[i] = a[i] ^ b[i];
  }

  return a;
}

function hash160(buffer) {
  return ripemd160(sha256(buffer));
}

function hash256(buffer) {
  return sha256(sha256(buffer));
}

function getAddress(d, compressed) {
  const Q = secp256k1.getPublicKey(d, compressed);
  const hash = hash160(Q);
  const payload = new Uint8Array(21);
  payload[0] = 0x00; // Bitcoin version byte
  payload.set(hash, 1);

  return bs58check.encode(payload);
}

function prepareEncryptRaw(buffer, compressed, passphrase, scryptParams) {
  if (buffer.length !== 32) throw new Error('Invalid private key length');

  let address = getAddress(buffer, compressed);
  let secret = new TextEncoder().encode(passphrase.normalize('NFC'));
  let salt = hash256(address).slice(0, 4);
  let { N, r, p } = scryptParams;

  return { secret, salt, N, r, p };
}

function finishEncryptRaw(buffer, compressed, salt, scryptBuf) {
  let derivedHalf1 = scryptBuf.slice(0, 32);
  let derivedHalf2 = scryptBuf.slice(32, 64);

  let xorBuf = xor(derivedHalf1, buffer);

  let stream = aes.ecb(derivedHalf2, { disablePadding: true });
  let cipherText = stream.encrypt(xorBuf);

  // 0x01 | 0x42 | flagByte | salt (4) | cipherText (32)
  let result = new Uint8Array(7 + cipherText.length);
  result[0] = 0x01;
  result[1] = 0x42;
  result[2] = compressed ? 0xe0 : 0xc0;
  result.set(salt, 3);
  result.set(cipherText, 7);

  return result;
}

async function encryptRawAsync(buffer, compressed, passphrase, onProgress, scryptParams) {
  scryptParams = scryptParams || SCRYPT_PARAMS;
  const { secret, salt, N, r, p } = prepareEncryptRaw(buffer, compressed, passphrase, scryptParams);

  let scryptBuf = new Uint8Array(
    await scryptAsync(secret, salt, { N, r, p, dkLen: 64, onProgress })
  );

  return finishEncryptRaw(buffer, compressed, salt, scryptBuf);
}

function encryptRaw(buffer, compressed, passphrase, onProgress, scryptParams) {
  scryptParams = scryptParams || SCRYPT_PARAMS;
  const { secret, salt, N, r, p } = prepareEncryptRaw(buffer, compressed, passphrase, scryptParams);

  let scryptBuf = new Uint8Array(scrypt(secret, salt, { N, r, p, dkLen: 64, onProgress }));

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
  buffer = new Uint8Array(buffer);

  // 39 bytes: 2 bytes prefix, 37 bytes payload
  if (buffer.length !== 39) throw new Error('Invalid BIP38 data length');
  if (buffer[0] !== 0x01) throw new Error('Invalid BIP38 prefix');

  // check if BIP38 EC multiply
  let type = buffer[1];
  if (type === 0x43) return { decryptEC: true };
  if (type !== 0x42) throw new Error('Invalid BIP38 type');

  let flagByte = buffer[2];
  let compressed = flagByte === 0xe0;
  if (!compressed && flagByte !== 0xc0) throw new Error('Invalid BIP38 compression flag');

  let { N, r, p } = scryptParams;

  let salt = buffer.slice(3, 7);
    return { salt, compressed, N, r, p };
}

function finishDecryptRaw(buffer, salt, compressed, scryptBuf) {
  let derivedHalf1 = scryptBuf.slice(0, 32);
  let derivedHalf2 = scryptBuf.slice(32, 64);

  let privKeyBuf = new Uint8Array(buffer.slice(7, 7 + 32));
  let stream = aes.ecb(derivedHalf2, { disablePadding: true });
  let plainText = stream.decrypt(privKeyBuf);

  let privateKey = xor(derivedHalf1, plainText);

  let address = getAddress(privateKey, compressed);
  let checksum = hash256(address).slice(0, 4);
  if (!equal(salt, checksum)) throw new Error('Invalid checksum');

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

  let scryptBuf = await scryptAsync(new TextEncoder().encode(passphrase.normalize('NFC')), salt, {
    N,
    r,
    p,
    dkLen: 64,
    onProgress,
  });
  return finishDecryptRaw(buffer, salt, compressed, scryptBuf);
}

function decryptRaw(buffer, passphrase, onProgress, scryptParams) {
  let bufferArray = new Uint8Array(buffer);
  scryptParams = scryptParams || SCRYPT_PARAMS;
  const { salt, compressed, N, r, p, decryptEC } = prepareDecryptRaw(
    bufferArray,
    onProgress,
    scryptParams
  );
  if (decryptEC === true) return decryptECMult(bufferArray, passphrase, onProgress, scryptParams);
  let scryptBuf = scrypt(new TextEncoder().encode(passphrase.normalize('NFC')), salt, {
    N,
    r,
    p,
    dkLen: 64,
    onProgress,
  });
  return finishDecryptRaw(bufferArray, salt, compressed, scryptBuf);
}

async function decryptAsync(string, passphrase, onProgress, scryptParams) {
  return decryptRawAsync(bs58check.decode(string), passphrase, onProgress, scryptParams);
}

function decrypt(string, passphrase, onProgress, scryptParams) {
  return decryptRaw(bs58check.decode(string), passphrase, onProgress, scryptParams);
}

function prepareDecryptECMult(buffer, passphrase, onProgress, scryptParams) {
  let flag = buffer[1];
  let compressed = (flag & 0x20) !== 0;
  let hasLotSeq = (flag & 0x04) !== 0;

  if ((flag & 0x24) !== flag) throw new Error('Invalid private key.');

  let addressHash = buffer.slice(2, 6);
  let ownerEntropy = buffer.slice(6, 14);
  let ownerSalt;

  // 4 bytes ownerSalt if 4 bytes lot/sequence
  if (hasLotSeq) {
    ownerSalt = ownerEntropy.slice(0, 4);

    // else, 8 bytes ownerSalt
  } else {
    ownerSalt = ownerEntropy;
  }

  let encryptedPart1 = buffer.slice(14, 22); // First 8 bytes
  let encryptedPart2 = buffer.slice(22, 38); // 16 bytes

  let N = scryptParams.N;
  let r = scryptParams.r;
  let p = scryptParams.p;
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
  let passFactor;
  if (hasLotSeq) {
    let hashTarget = new Uint8Array([...preFactor, ...ownerEntropy]);
    passFactor = hash256(hashTarget);
  } else {
    passFactor = preFactor;
  }

  let passInt = bytesToNumberBE(passFactor);
  return {
    passInt,
    passPoint: secp256k1.ProjectivePoint.fromPrivateKey(passFactor).toRawBytes(true),
  };
}

function finishDecryptECMult(seedBPass, encryptedPart1, encryptedPart2, passInt, compressed) {
  let derivedHalf1 = seedBPass.slice(0, 32);
  let derivedHalf2 = seedBPass.slice(32, 64);

  let stream = aes.ecb(derivedHalf2, { disablePadding: true });

  let decryptedPart2 = stream.decrypt(encryptedPart2);
  let tmp = xor(decryptedPart2, derivedHalf1.slice(16, 32));
  let seedBPart2 = tmp.slice(8, 16);

  // Reusing the stream for the second part of decryption
  let seedBPart1 = xor(
    stream.decrypt(new Uint8Array([...encryptedPart1, ...tmp.slice(0, 8)])),
    derivedHalf1.slice(0, 16)
  );
  let seedB = new Uint8Array([...seedBPart1, ...seedBPart2]);
  let factorB = hash256(seedB);

  // d = passFactor * factorB (mod n)
  let d = mod(passInt * bytesToNumberBE(factorB), secp256k1.CURVE.n);

  return { privateKey: numberToBytesBE(d), compressed };
}

async function decryptECMultAsync(buffer, passphrase, onProgress, scryptParams) {
  buffer = buffer.slice(1); // FIXME: we can avoid this
  passphrase = new TextEncoder().encode(passphrase.normalize('NFC'));
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

  let preFactor = await scryptAsync(passphrase, ownerSalt, {
    N,
    r,
    p,
    dkLen: 32,
    onProgress,
  });

  const { passInt, passPoint } = getPassIntAndPoint(preFactor, ownerEntropy, hasLotSeq);

  let seedBPass = await scryptAsync(passPoint, new Uint8Array([...addressHash, ...ownerEntropy]), {
    N: 1024,
    r: 1,
    p: 1,
    dkLen: 64,
  });

  return finishDecryptECMult(seedBPass, encryptedPart1, encryptedPart2, passInt, compressed);
}

function decryptECMult(buffer, passphrase, onProgress, scryptParams) {
  buffer = buffer.slice(1); // FIXME: we can avoid this
  passphrase = new TextEncoder().encode(passphrase.normalize('NFC'));
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
  let preFactor = scrypt(passphrase, ownerSalt, {
    N,
    r,
    p,
    dkLen: 32,
    onProgress,
  });

  const { passInt, passPoint } = getPassIntAndPoint(preFactor, ownerEntropy, hasLotSeq);

  let seedBPass = scrypt(passPoint, new Uint8Array([...addressHash, ...ownerEntropy]), {
    N: 1024,
    r: 1,
    p: 1,
    dkLen: 64,
  });

  return finishDecryptECMult(seedBPass, encryptedPart1, encryptedPart2, passInt, compressed);
}

function verify(string) {
  let decoded;
  try {
    decoded = bs58check.decode(string);
  } catch (e) {
    return false;
  }

  if (decoded.length !== 39) return false;
  if (decoded[0] !== 0x01) return false;

  let type = decoded[1];
  let flag = decoded[2];

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
  decrypt,
  decryptECMult,
  decryptRaw,
  encrypt,
  encryptRaw,
  decryptAsync,
  decryptECMultAsync,
  decryptRawAsync,
  encryptAsync,
  encryptRawAsync,
  verify,
};
