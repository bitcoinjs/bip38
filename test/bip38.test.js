var Bip38 = null

//node.js or mochify
if (typeof module != 'undefined' && module.exports) {
  Bip38 = require('../');
  require('terst');
} else { //manually running browser-test.js
  Bip38 = window.mod;
}

var fixtures = require('./fixtures/bip38')

describe('bip38', function() {
  fixtures.valid.forEach(function(f) {
    it('should encrypt and decrypt ' + f.description, function() {
      var bip38 = new Bip38()
      if (!f.decryptOnly)
        EQ (bip38.encrypt(f.wif, f.passphrase, f.address), f.bip38)
      EQ (bip38.decrypt(f.bip38, f.passphrase), f.wif)
    })
  })
})


describe('+ bip38', function() {
  describe('> when no EC multiply', function() {
    describe.skip('> when no compression', function() {

      describe('> when incorrect passphrase', function() {
        it('should throw an exception', function() {
          var passphrase = 'Satoshi';
          var encrypted = '6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq';
          var unencryptedWIF = '5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5';
          var unencryptedHex = '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE';
          var address = '1AvKt49sui9zfzGeo8EyL8ypvAhtR2KwbL';

          var bip38 = new Bip38();
          var err = null;
          try {
            var res = bip38.decrypt(encrypted, "Not Satoshi.", address);
            console.log(res)
          } catch (e) {
            err = e
          }

          EQ (err.message, 'Incorrect passphrase');
        })
      })
    })

  })
})