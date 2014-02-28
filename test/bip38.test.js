var Bip38 = require('../')

require('terst')

describe('+ bip38', function() {
  describe('> when no EC multiply', function() {
    describe('> when no compression', function() {
      it('test #1', function() {
        var passphrase = 'TestingOneTwoThree';
        var encrypted = '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg';
        var unencryptedWIF = '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR';
        var unencryptedHex = 'cbf4b9f70470856bb4f40f80b87edb90865997ffee6df315ab166d713af433a5';
        var address = "1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB";

        var bip38 = new Bip38();
        EQ (bip38.encrypt(unencryptedWIF, passphrase, address), encrypted);
        EQ (bip38.decrypt(encrypted, passphrase, address), unencryptedWIF);
      })

      it('test #2', function() {
        var passphrase = 'Satoshi';
        var encrypted = '6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq';
        var unencryptedWIF = '5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5';
        var unencryptedHex = '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE';
        var address = '1AvKt49sui9zfzGeo8EyL8ypvAhtR2KwbL';

        var bip38 = new Bip38();
        EQ (bip38.encrypt(unencryptedWIF, passphrase, address), encrypted);
        EQ (bip38.decrypt(encrypted, passphrase, address), unencryptedWIF);
      })
    })

    describe('> when compression', function() {
      it('test #1', function() {
        var passphrase = 'TestingOneTwoThree';
        var encrypted = '6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo';
        var unencryptedWIF = 'L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP';
        var unencryptedHex = 'CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5';
        var address = '164MQi977u9GUteHr4EPH27VkkdxmfCvGW';

        var bip38 = new Bip38();
        EQ (bip38.encrypt(unencryptedWIF, passphrase, address), encrypted);
        EQ (bip38.decrypt(encrypted, passphrase, address), unencryptedWIF);
      })

      it('test #2', function() {
        var passphrase = 'Satoshi';
        var encrypted = '6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7';
        var unencryptedWIF = 'KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7';
        var unencryptedHex = '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE';
        var address = "1HmPbwsvG5qJ3KJfxzsZRZWhbm1xBMuS8B";

        var bip38 = new Bip38();
        EQ (bip38.encrypt(unencryptedWIF, passphrase, address), encrypted);
        EQ (bip38.decrypt(encrypted, passphrase, address), unencryptedWIF);
      })
    })
  })

  describe.skip('> when EC multiply', function() {
    describe('> when no compression, no lot/sequence numbers', function() {
      it('test #1', function() {
        var passphrase = 'TestingOneTwoThree';
        var passphraseCode = 'passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm';
        var encrypted = '6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX';
        var bitcoinAddress = '1PE6TQi6HTVNz5DLwB1LcpMBALubfuN2z2';
        var unencryptedWIF = '5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2';
        var unencryptedHex = 'A43A940577F4E97F5C4D39EB14FF083A98187C64EA7C99EF7CE460833959A519';
      })

      it('test #2', function() {
        var passphrase = 'Satoshi';
        var passphraseCode = 'passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS';
        var encrypted = '6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd';
        var bitcoinAddress = '1CqzrtZC6mXSAhoxtFwVjz8LtwLJjDYU3V';
        var unencryptedWIF = '5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH';
        var unencryptedHex = 'C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A';
      })
    })

    describe('> when no compression, lot/sequence numbers', function() {
      it('test #1', function() {
        var passphrase = 'MOLON LABE';
        var passphraseCode = 'passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX';
        var encrypted = '6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j';
        var bitcoinAddress = '1Jscj8ALrYu2y9TD8NrpvDBugPedmbj4Yh';
        var unencryptedWIF = '5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8';
        var unencryptedHex = '44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190';
        var confirmationCode = 'cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPD';
        var lot = 263183;
        var seq = 1;
      })

      it('test #2', function() {
        var passphrase = 'ΜΟΛΩΝ ΛΑΒΕ';
        var passphraseCode = 'passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK';
        var encrypted = '6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH';
        var bitcoinAddress = '1Lurmih3KruL4xDB5FmHof38yawNtP9oGf';
        var unencryptedWIF = '5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D';
        var unencryptedHex = 'CA2759AA4ADB0F96C414F36ABEB8DB59342985BE9FA50FAAC228C8E7D90E3006';
        var confirmationCode = 'cfrm38V8G4qq2ywYEFfWLD5Cc6msj9UwsG2Mj4Z6QdGJAFQpdatZLavkgRd1i4iBMdRngDqDs51';  
        var lot = 806938;
        var sequence = 1;
      })
    })
  })
})