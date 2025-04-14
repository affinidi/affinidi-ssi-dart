import 'package:convert/convert.dart';

import 'dart:convert';
import 'dart:typed_data';

import 'package:bip32/bip32.dart';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final keyId = 'keyId';
  final data = Uint8List.fromList([1, 2, 3, 4]);
  final Uint8List privateKey = Uint8List.fromList([227, 35, 123, 65, 230, 94, 167, 239, 43, 209, 58, 97, 123, 14, 35, 244, 8, 115, 55, 216, 244, 132, 3, 14, 52, 56, 255, 214, 91, 83, 88, 177]);
  final Uint8List privateKeyBob = Uint8List.fromList([227, 35, 123, 65, 230, 94, 167, 239, 43, 209, 58, 97, 123, 14, 35, 244, 8, 115, 55, 216, 244, 132, 3, 14, 52, 56, 255, 214, 91, 83, 88, 177]);
  final Uint8List publicKey = Uint8List.fromList([154, 91, 111, 200, 105, 249, 92, 207, 158, 65, 234, 210, 123, 83, 171, 151, 40, 204, 225, 21, 100, 80, 98, 246, 210, 65, 29, 151, 214, 17, 13, 132]);

  group('Test key pair encrypt decrypt', () {
    test('ed25519', () async {
      Secp256k1KeyPair secp = Secp256k1KeyPair(
        node: BIP32.fromPrivateKey(privateKey, Uint8List(32)), // Empty chain code
        keyId: keyId,
      );

      // Encrypt with ephemeral key
      var encrypted = await secp.encrypt(data);
      // Decrypt the message
      var decrypted = await secp.decrypt(encrypted);

      expect(decrypted, data);
    });


    test('Secp256k1 without pub key', () async {
      Uint8List chainCode = Uint8List(32); // Empty chain code (32 bytes)
      Secp256k1KeyPair secp = Secp256k1KeyPair(
        node: BIP32.fromPrivateKey(privateKey, chainCode),
        keyId: keyId
      );

      // var publicKey = secp.generateEphemeralPubKey();
      // var secret = secp.computeEcdhSecret(publicKey);
      var encrypted = await secp.encrypt(data);

      var decrypted = await secp.decrypt(encrypted);

      expect(decrypted, data);
    });

    test('Secp256k1 with pub key parameter', () async {
      Uint8List chainCode = Uint8List(32); // Empty chain code (32 bytes)
      Secp256k1KeyPair secpAlice = Secp256k1KeyPair(
        node: BIP32.fromPrivateKey(privateKey, chainCode),
        keyId: keyId
      );

      Secp256k1KeyPair secpBob = Secp256k1KeyPair(
        node: BIP32.fromPrivateKey(privateKeyBob, chainCode),
        keyId: keyId
      );

      var bobPubKey = await secpBob.publicKey;
      var encryptedByAlice = await secpAlice.encrypt(data, publicKey: bobPubKey);

      var alicePubKey = await secpAlice.publicKey;
      var decryptedByBob = await secpBob.decrypt(encryptedByAlice, publicKey: alicePubKey);

      expect(decryptedByBob, data);
    });
  });
}
