import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final keyId = 'keyId';
  final data = Uint8List.fromList([1, 2, 3, 4]);
  final Uint8List privateKey = Uint8List.fromList([
    227,
    35,
    123,
    65,
    230,
    94,
    167,
    239,
    43,
    209,
    58,
    97,
    123,
    14,
    35,
    244,
    8,
    115,
    55,
    216,
    244,
    132,
    3,
    14,
    52,
    56,
    255,
    214,
    91,
    83,
    88,
    177
  ]);
  final Uint8List privateKeyBob = Uint8List.fromList([
    227,
    35,
    123,
    65,
    230,
    94,
    167,
    239,
    43,
    209,
    58,
    167,
    123,
    14,
    35,
    244,
    8,
    115,
    55,
    216,
    244,
    132,
    3,
    14,
    52,
    56,
    255,
    214,
    91,
    83,
    88,
    177
  ]);
  // final Uint8List publicKey = Uint8List.fromList([154, 91, 111, 200, 105, 249, 92, 207, 158, 65, 234, 210, 123, 83, 171, 151, 40, 204, 225, 21, 100, 80, 98, 246, 210, 65, 29, 151, 214, 17, 13, 132]);

  final Uint8List edSeedAlice = Uint8List.fromList([
    23,
    28,
    184,
    139,
    27,
    60,
    29,
    178,
    90,
    221,
    89,
    151,
    18,
    227,
    98,
    69,
    215,
    91,
    198,
    90,
    26,
    92,
    158,
    24,
    215,
    111,
    159,
    43,
    30,
    171,
    64,
    18
  ]);
  final Uint8List edSeedBob = Uint8List.fromList([
    13,
    36,
    195,
    44,
    220,
    172,
    66,
    97,
    46,
    102,
    231,
    86,
    39,
    125,
    84,
    16,
    164,
    17,
    101,
    182,
    174,
    121,
    215,
    121,
    110,
    94,
    219,
    86,
    89,
    176,
    187,
    129
  ]);

  group('Test key pair encrypt decrypt', () {
    test('ed25519', () async {
      Ed25519KeyPair edKey = Ed25519KeyPair(
          privateKey: ed.newKeyFromSeed(edSeedAlice), keyId: keyId);
      // Encrypt with ephemeral key
      var encrypted = await edKey.encrypt(data);
      // Decrypt the message
      var decrypted = await edKey.decrypt(encrypted);

      expect(decrypted, data);
    });

    test('ed25519 with pub key parameter', () async {
      Ed25519KeyPair edAlice = Ed25519KeyPair(
          privateKey: ed.newKeyFromSeed(edSeedAlice), keyId: keyId);
      Ed25519KeyPair edBob = Ed25519KeyPair(
          privateKey: ed.newKeyFromSeed(edSeedBob), keyId: keyId);

      var bobPubKey = await edBob.ed25519KeyToX25519PublicKey();
      var encryptedByAlice = await edAlice.encrypt(data,
          publicKey: Uint8List.fromList(bobPubKey.bytes));

      var alicePubKey = await edAlice.ed25519KeyToX25519PublicKey();
      var decryptedByBob = await edBob.decrypt(encryptedByAlice,
          publicKey: Uint8List.fromList(alicePubKey.bytes));

      expect(decryptedByBob, data);
    });

    test('Secp256k1 without pub key', () async {
      Uint8List chainCode = Uint8List(32); // Empty chain code (32 bytes)
      Secp256k1KeyPair secp = Secp256k1KeyPair(
          node: BIP32.fromPrivateKey(privateKey, chainCode), keyId: keyId);

      var encrypted = await secp.encrypt(data);

      var decrypted = await secp.decrypt(encrypted);

      expect(decrypted, data);
    });

    test('Secp256k1 with pub key parameter', () async {
      Uint8List chainCode = Uint8List(32); // Empty chain code (32 bytes)
      Secp256k1KeyPair secpAlice = Secp256k1KeyPair(
          node: BIP32.fromPrivateKey(privateKey, chainCode), keyId: keyId);

      Secp256k1KeyPair secpBob = Secp256k1KeyPair(
          node: BIP32.fromPrivateKey(privateKeyBob, chainCode), keyId: keyId);

      var bobPubKey = await secpBob.publicKey;
      var encryptedByAlice =
          await secpAlice.encrypt(data, publicKey: bobPubKey);

      var alicePubKey = await secpAlice.publicKey;
      var decryptedByBob =
          await secpBob.decrypt(encryptedByAlice, publicKey: alicePubKey);

      expect(decryptedByBob, data);
    });
  });
}
