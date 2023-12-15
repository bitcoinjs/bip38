/* global describe, it */

import assert from "assert";
import { sha256 } from "@noble/hashes/sha256";
import bs58check from "bs58check";
import * as bip38 from "../index.js";
import fixtures from "./fixtures.js";

function concat(...arrays) {
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

const wif = {
  encode(prefix, privKey, compressed) {
    let k = privKey;
    if (compressed) k = concat(privKey, new Uint8Array([0x01]));
    return bs58check.encode(concat(Uint8Array.from([prefix]), k));
  },
};

function replaceUnicode(str) {
  const map = {
    "\\u03D2\\u0301\\u{0000}\\u{00010400}\\u{0001F4A9}":
      "\u03D2\u0301\u{0000}\u{00010400}\u{0001F4A9}",
  };
  return map[str] || str;
}

describe("bip38", function () {
  this.timeout(200000);

  describe("decrypt", () => {
    for (const f of fixtures.valid) {
      it(`should decrypt ${f.description}`, () => {
        const result = bip38.decrypt(f.bip38, replaceUnicode(f.passphrase));

        assert.strictEqual(
          wif.encode(0x80, result.privateKey, result.compressed),
          f.wif,
        );
      });
    }

    for (const f of fixtures.invalid.decrypt) {
      it(`should throw ${f.description}`, () => {
        assert.throws(() => {
          bip38.decrypt(f.bip38, f.passphrase);
        }, new RegExp(f.description, "i"));
      });
    }

    for (const f of fixtures.invalid.verify) {
      it(`should throw because ${f.description}`, () => {
        assert.throws(() => {
          bip38.decrypt(f.base58, "foobar");
        }, new RegExp(f.exception));
      });
    }
  });

  describe("encrypt", () => {
    for (const f of fixtures.valid) {
      if (f.decryptOnly) return;

      it(`should encrypt ${f.description}`, () => {
        const buffer = bs58check.decode(f.wif);

        assert.strictEqual(
          bip38.encrypt(
            buffer.slice(1, 33),
            !!buffer[33],
            replaceUnicode(f.passphrase),
          ),
          f.bip38,
        );
      });
    }
  });

  describe("decryptAsync", () => {
    for (const f of fixtures.valid) {
      it(`should decrypt ${f.description}`, async () => {
        const result = await bip38.decryptAsync(
          f.bip38,
          replaceUnicode(f.passphrase),
        );

        assert.strictEqual(
          wif.encode(0x80, result.privateKey, result.compressed),
          f.wif,
        );
      });
    }

    for (const f of fixtures.invalid.decrypt) {
      it(`should throw ${f.description}`, async () => {
        assert.rejects(async () => {
          await bip38.decryptAsync(f.bip38, replaceUnicode(f.passphrase));
        }, new RegExp(f.description, "i"));
      });
    }

    for (const f of fixtures.invalid.verify) {
      it(`should throw because ${f.description}`, async () => {
        assert.rejects(async () => {
          await bip38.decryptAsync(f.base58, "foobar");
        }, new RegExp(f.exception));
      });
    }
  });

  describe("encryptAsync", () => {
    for (const f of fixtures.valid) {
      if (f.decryptOnly) return;

      it(`should encrypt ${f.description}`, async () => {
        const buffer = bs58check.decode(f.wif);

        assert.strictEqual(
          await bip38.encryptAsync(
            buffer.slice(1, 33),
            !!buffer[33],
            replaceUnicode(f.passphrase),
          ),
          f.bip38,
        );
      });
    }
  });

  describe("verify", () => {
    for (const f of fixtures.valid) {
      it(`should return true for ${f.bip38}`, () => {
        assert(bip38.verify(f.bip38));
      });
    }

    for (const f of fixtures.invalid.verify) {
      it(`should return false for ${f.description}`, () => {
        assert(!bip38.verify(f.base58));
      });
    }
  });
});
