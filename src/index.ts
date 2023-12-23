import { ecb } from "@noble/ciphers/aes";
import { mod } from "@noble/curves/abstract/modular";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/abstract/utils";
import { secp256k1 } from "@noble/curves/secp256k1";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { scrypt, scryptAsync } from "@noble/hashes/scrypt";
import { sha256 } from "@noble/hashes/sha256";
import bs58check from "bs58check";
import TextEncoder from './encoder.js';

// constants
const SCRYPT_PARAMS = {
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
  const length = Math.min(a.length, b.length);

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
  if (buffer.length !== 32) throw new Error("Invalid private key length");

  const address = getAddress(buffer, compressed);
  const secret = new TextEncoder().encode(passphrase.normalize("NFC"));

  const salt = hash256(address).slice(0, 4);
  const { N, r, p } = scryptParams;

  return { secret, salt, N, r, p };
}

function finishEncryptRaw(buffer, compressed, salt, scryptBuf) {
  const derivedHalf1 = scryptBuf.slice(0, 32);
  const derivedHalf2 = scryptBuf.slice(32, 64);

  const xorBuf = xor(derivedHalf1, buffer);

  const stream = ecb(derivedHalf2, { disablePadding: true });
  const cipherText = stream.encrypt(xorBuf);

  // 0x01 | 0x42 | flagByte | salt (4) | cipherText (32)
  const result = new Uint8Array(7 + cipherText.length);
  result[0] = 0x01;
  result[1] = 0x42;
  result[2] = compressed ? 0xe0 : 0xc0;
  result.set(salt, 3);
  result.set(cipherText, 7);

  return result;
}

async function encryptRawAsync(
  buffer,
  compressed,
  passphrase,
  onProgress,
  scryptParams = SCRYPT_PARAMS,
) {
  const { secret, salt, N, r, p } = prepareEncryptRaw(
    buffer,
    compressed,
    passphrase,
    scryptParams,
  );

  const scryptBuf = new Uint8Array(
    await scryptAsync(secret, salt, { N, r, p, dkLen: 64, onProgress }),
  );

  return finishEncryptRaw(buffer, compressed, salt, scryptBuf);
}

export function encryptRaw(
  buffer,
  compressed,
  passphrase,
  onProgress,
  scryptParams = SCRYPT_PARAMS,
) {
  const { secret, salt, N, r, p } = prepareEncryptRaw(
    buffer,
    compressed,
    passphrase,
    scryptParams,
  );

  const scryptBuf = new Uint8Array(
    scrypt(secret, salt, { N, r, p, dkLen: 64, onProgress }),
  );

  return finishEncryptRaw(buffer, compressed, salt, scryptBuf);
}

export async function encryptAsync(
  buffer,
  compressed,
  passphrase,
  onProgress,
  scryptParams,
) {
  return bs58check.encode(
    await encryptRawAsync(
      buffer,
      compressed,
      passphrase,
      onProgress,
      scryptParams,
    ),
  );
}

export function encrypt(
  buffer,
  compressed,
  passphrase,
  onProgress,
  scryptParams,
) {
  return bs58check.encode(
    encryptRaw(buffer, compressed, passphrase, onProgress, scryptParams),
  );
}

function prepareDecryptRaw(buffer, onProgress, scryptParams) {
  // 39 bytes: 2 bytes prefix, 37 bytes payload
  if (buffer.length !== 39) throw new Error("Invalid BIP38 data length");
  if (buffer[0] !== 0x01) throw new Error("Invalid BIP38 prefix");

  // check if BIP38 EC multiply
  const type = buffer[1];
  if (type === 0x43) return { decryptEC: true };
  if (type !== 0x42) throw new Error("Invalid BIP38 type");

  const flagByte = buffer[2];
  const compressed = flagByte === 0xe0;
  if (!compressed && flagByte !== 0xc0)
    throw new Error("Invalid BIP38 compression flag");

  const { N, r, p } = scryptParams;

  const salt = buffer.slice(3, 7);
  return { salt, compressed, N, r, p };
}

function finishDecryptRaw(buffer, salt, compressed, scryptBuf) {
  const derivedHalf1 = scryptBuf.slice(0, 32);
  const derivedHalf2 = scryptBuf.slice(32, 64);

  const privKeyBuf = new Uint8Array(buffer.slice(7, 7 + 32));
  const stream = ecb(derivedHalf2, { disablePadding: true });
  const plainText = stream.decrypt(privKeyBuf);

  const privateKey = xor(derivedHalf1, plainText);

  const address = getAddress(privateKey, compressed);
  const checksum = hash256(address).slice(0, 4);
  if (!equal(salt, checksum)) throw new Error("Invalid checksum");

  return {
    privateKey: privateKey,
    compressed: compressed,
  };
}

export async function decryptRawAsync(
  buffer,
  passphrase,
  onProgress,
  scryptParams = SCRYPT_PARAMS,
) {
  const { salt, compressed, N, r, p, decryptEC } = prepareDecryptRaw(
    buffer,
    onProgress,
    scryptParams,
  );
  if (decryptEC === true)
    return decryptECMultAsync(buffer, passphrase, onProgress, scryptParams);

  const scryptBuf = await scryptAsync(
    new TextEncoder().encode(passphrase.normalize("NFC")),
    salt,
    {
      N,
      r,
      p,
      dkLen: 64,
      onProgress,
    },
  );
  return finishDecryptRaw(buffer, salt, compressed, scryptBuf);
}

export function decryptRaw(
  buffer,
  passphrase,
  onProgress,
  scryptParams = SCRYPT_PARAMS,
) {
  const bufferArray = new Uint8Array(buffer);
  const { salt, compressed, N, r, p, decryptEC } = prepareDecryptRaw(
    bufferArray,
    onProgress,
    scryptParams,
  );
  if (decryptEC === true)
    return decryptECMult(bufferArray, passphrase, onProgress, scryptParams);
  const scryptBuf = scrypt(
    new TextEncoder().encode(passphrase.normalize("NFC")),
    salt,
    {
      N,
      r,
      p,
      dkLen: 64,
      onProgress,
    },
  );
  return finishDecryptRaw(bufferArray, salt, compressed, scryptBuf);
}

export async function decryptAsync(
  string,
  passphrase,
  onProgress,
  scryptParams,
) {
  return decryptRawAsync(
    bs58check.decode(string),
    passphrase,
    onProgress,
    scryptParams,
  );
}

export function decrypt(string, passphrase, onProgress, scryptParams) {
  return decryptRaw(
    bs58check.decode(string),
    passphrase,
    onProgress,
    scryptParams,
  );
}

function prepareDecryptECMult(buffer, passphrase, onProgress, scryptParams) {
  const flag = buffer[1];
  const compressed = (flag & 0x20) !== 0;
  const hasLotSeq = (flag & 0x04) !== 0;

  if ((flag & 0x24) !== flag) throw new Error("Invalid private key.");

  const addressHash = buffer.slice(2, 6);
  const ownerEntropy = buffer.slice(6, 14);
  let ownerSalt;

  // 4 bytes ownerSalt if 4 bytes lot/sequence
  if (hasLotSeq) {
    ownerSalt = ownerEntropy.slice(0, 4);

    // else, 8 bytes ownerSalt
  } else {
    ownerSalt = ownerEntropy;
  }

  const encryptedPart1 = buffer.slice(14, 22); // First 8 bytes
  const encryptedPart2 = buffer.slice(22, 38); // 16 bytes

  const N = scryptParams.N;
  const r = scryptParams.r;
  const p = scryptParams.p;
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
    const hashTarget = new Uint8Array([...preFactor, ...ownerEntropy]);
    passFactor = hash256(hashTarget);
  } else {
    passFactor = preFactor;
  }

  const passInt = bytesToNumberBE(passFactor);
  return {
    passInt,
    passPoint:
      secp256k1.ProjectivePoint.fromPrivateKey(passFactor).toRawBytes(true),
  };
}

function finishDecryptECMult(
  seedBPass,
  encryptedPart1,
  encryptedPart2,
  passInt,
  compressed,
) {
  const derivedHalf1 = seedBPass.slice(0, 32);
  const derivedHalf2 = seedBPass.slice(32, 64);

  const stream = ecb(derivedHalf2, { disablePadding: true });

  const decryptedPart2 = stream.decrypt(encryptedPart2);
  const tmp = xor(decryptedPart2, derivedHalf1.slice(16, 32));
  const seedBPart2 = tmp.slice(8, 16);

  // Reusing the stream for the second part of decryption
  const seedBPart1 = xor(
    stream.decrypt(new Uint8Array([...encryptedPart1, ...tmp.slice(0, 8)])),
    derivedHalf1.slice(0, 16),
  );
  const seedB = new Uint8Array([...seedBPart1, ...seedBPart2]);
  const factorB = hash256(seedB);

  // d = passFactor * factorB (mod n)
  const d = mod(passInt * bytesToNumberBE(factorB), secp256k1.CURVE.n);

  return { privateKey: numberToBytesBE(d, 32), compressed };
}

export async function decryptECMultAsync(
  buffer,
  passphrase,
  onProgress,
  scryptParams = SCRYPT_PARAMS,
) {
  const secret = new TextEncoder().encode(passphrase.normalize("NFC"));

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
  } = prepareDecryptECMult(buffer.slice(1), secret, onProgress, scryptParams);

  const preFactor = await scryptAsync(secret, ownerSalt, {
    N,
    r,
    p,
    dkLen: 32,
    onProgress,
  });

  const { passInt, passPoint } = getPassIntAndPoint(
    preFactor,
    ownerEntropy,
    hasLotSeq,
  );

  const seedBPass = await scryptAsync(
    passPoint,
    new Uint8Array([...addressHash, ...ownerEntropy]),
    {
      N: 1024,
      r: 1,
      p: 1,
      dkLen: 64,
    },
  );

  return finishDecryptECMult(
    seedBPass,
    encryptedPart1,
    encryptedPart2,
    passInt,
    compressed,
  );
}

export function decryptECMult(
  buffer,
  passphrase,
  onProgress,
  scryptParams = SCRYPT_PARAMS,
) {
  const secret = new TextEncoder().encode(passphrase.normalize("NFC"));
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
  } = prepareDecryptECMult(buffer.slice(1), secret, onProgress, scryptParams);
  const preFactor = scrypt(secret, ownerSalt, {
    N,
    r,
    p,
    dkLen: 32,
    onProgress,
  });

  const { passInt, passPoint } = getPassIntAndPoint(
    preFactor,
    ownerEntropy,
    hasLotSeq,
  );

  const seedBPass = scrypt(
    passPoint,
    new Uint8Array([...addressHash, ...ownerEntropy]),
    {
      N: 1024,
      r: 1,
      p: 1,
      dkLen: 64,
    },
  );

  return finishDecryptECMult(
    seedBPass,
    encryptedPart1,
    encryptedPart2,
    passInt,
    compressed,
  );
}

export function verify(string) {
  let decoded;
  try {
    decoded = bs58check.decode(string);
  } catch (e) {
    return false;
  }

  if (decoded.length !== 39) return false;
  if (decoded[0] !== 0x01) return false;

  const type = decoded[1];
  const flag = decoded[2];

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

export default {
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
