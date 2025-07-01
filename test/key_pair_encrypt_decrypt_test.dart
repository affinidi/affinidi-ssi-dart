import 'dart:typed_data';

import 'package:bip32_plus/bip32_plus.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final data = Uint8List.fromList([1, 2, 3, 4]);
  final privateKey = Uint8List.fromList([
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
  final privateKeyBob = Uint8List.fromList([
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

  final edSeedAlice = Uint8List.fromList([
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
  final edSeedBob = Uint8List.fromList([
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
    test('p256 without pub key', () async {
      var (p256Key, privateKeyBytes) = P256KeyPair.generate();
      // Encrypt with ephemeral key
      var encrypted = await p256Key.encrypt(data);
      // Decrypt the message
      var decrypted = await p256Key.decrypt(encrypted);

      expect(decrypted, data);
    });

    test('p256 with pub key parameter', () async {
      var (p256KeyAlice, aliceKeyBytes) = P256KeyPair.generate();
      var (p256KeyBob, bobKeyBytes) = P256KeyPair.generate();

      var bobPubKey = p256KeyBob.publicKey;
      var encryptedByAlice =
          await p256KeyAlice.encrypt(data, publicKey: bobPubKey.bytes);

      var alicePubKey = p256KeyAlice.publicKey;
      var decryptedByBob = await p256KeyBob.decrypt(encryptedByAlice,
          publicKey: alicePubKey.bytes);

      expect(decryptedByBob, data);
    });

    test('ed25519 without pub key', () async {
      var edKey = Ed25519KeyPair.fromSeed(edSeedAlice);
      // Encrypt with ephemeral key
      var encrypted = await edKey.encrypt(data);
      // Decrypt the message
      var decrypted = await edKey.decrypt(encrypted);

      expect(decrypted, data);
    });

    test('ed25519 with pub key parameter', () async {
      var edAlice = Ed25519KeyPair.fromSeed(edSeedAlice);
      var edBob = Ed25519KeyPair.fromSeed(edSeedBob);

      var bobPubKey = await edBob.ed25519KeyToX25519PublicKey();
      var encryptedByAlice =
          await edAlice.encrypt(data, publicKey: bobPubKey.bytes);

      var alicePubKey = await edAlice.ed25519KeyToX25519PublicKey();
      var decryptedByBob =
          await edBob.decrypt(encryptedByAlice, publicKey: alicePubKey.bytes);

      expect(decryptedByBob, data);
    });

    test('Secp256k1 without pub key', () async {
      var chainCode = Uint8List(32); // Empty chain code (32 bytes)
      var secp =
          Secp256k1KeyPair(node: BIP32.fromPrivateKey(privateKey, chainCode));

      var encrypted = await secp.encrypt(data);

      var decrypted = await secp.decrypt(encrypted);

      expect(decrypted, data);
    });

    test('Secp256k1 with pub key parameter', () async {
      var chainCode = Uint8List(32); // Empty chain code (32 bytes)
      var secpAlice =
          Secp256k1KeyPair(node: BIP32.fromPrivateKey(privateKey, chainCode));

      var secpBob = Secp256k1KeyPair(
          node: BIP32.fromPrivateKey(privateKeyBob, chainCode));

      var bobPubKey = secpBob.publicKey;
      var encryptedByAlice =
          await secpAlice.encrypt(data, publicKey: bobPubKey.bytes);

      var alicePubKey = secpAlice.publicKey;
      var decryptedByBob =
          await secpBob.decrypt(encryptedByAlice, publicKey: alicePubKey.bytes);

      expect(decryptedByBob, data);
    });
  });
}
