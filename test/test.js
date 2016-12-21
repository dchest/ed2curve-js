var test = require('tape');
var nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');
var ed2curve = require('../ed2curve');

test('ed2curve.convertKeyPair (seed)', function(t) {
  var mySeed = new Uint8Array(32);
  for (var i = 0; i < 32; i++) mySeed[i] = i;
  var peerSeed = new Uint8Array(32);
  for (var i = 0; i < 32; i++) peerSeed[i] = i+100;

  signKeys = nacl.sign.keyPair.fromSeed(mySeed);
  dhKeys = ed2curve.convertKeyPair(signKeys);
  t.ok(dhKeys.publicKey, 'should convert public key');

  dhPeerKeys = nacl.box.keyPair.fromSecretKey(peerSeed);
  var s1 = nacl.box.before(dhKeys.publicKey, dhPeerKeys.secretKey);
  var s2 = nacl.box.before(dhPeerKeys.publicKey, dhKeys.secretKey);
  t.equal(nacl.util.encodeBase64(s2), nacl.util.encodeBase64(s1));
  t.end();
});

test('ed2curve.convertKeyPair (random)', function(t) {
  var signKeys = nacl.sign.keyPair();
  var dhKeys = ed2curve.convertKeyPair(signKeys);
  var dhPeerKeys = nacl.box.keyPair();

  var message = 'I am converting keys!';
  var m = nacl.util.decodeUTF8(message);
  var n = nacl.randomBytes(24);
  var box = nacl.box(m, n, dhKeys.publicKey, dhPeerKeys.secretKey);
  var unbox = nacl.box.open(box, n, dhPeerKeys.publicKey, dhKeys.secretKey);
  t.ok(unbox, 'should open box');
  t.equal(nacl.util.encodeUTF8(unbox), message);
  t.end();
});

test('ed2curve.convertSecretKey and ed2curve.convertPublicKey (random)', function(t) {
  var mySignKeys = nacl.sign.keyPair();
  var theirSignKeys = nacl.sign.keyPair();

  var myDHPublicKey = ed2curve.convertPublicKey(mySignKeys.publicKey);
  var theirDHPublicKey = ed2curve.convertPublicKey(theirSignKeys.publicKey);

  t.equal(myDHPublicKey.length, 32);
  t.equal(theirDHPublicKey.length, 32);

  var myDHSecretKey = ed2curve.convertSecretKey(mySignKeys.secretKey);
  var theirDHSecretKey = ed2curve.convertSecretKey(theirSignKeys.secretKey);

  t.equal(myDHSecretKey.length, 32);
  t.equal(theirDHSecretKey.length, 32);

  var s1 = nacl.box.before(theirDHPublicKey, myDHSecretKey);
  var s2 = nacl.box.before(myDHPublicKey, theirDHSecretKey);
  t.equal(nacl.util.encodeBase64(s2), nacl.util.encodeBase64(s1));
  t.end();
});

test('ed2curve.convertPublicKey (invalid key)', function(t) {
  var invalidKey = new Uint8Array(32);
  for (var i = 0; i < 31; i++) invalidKey[i] = 0xff;
  var pk = ed2curve.convertPublicKey(invalidKey);
  t.equal(pk, null);
  t.end();
});
