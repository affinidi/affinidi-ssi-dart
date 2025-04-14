import 'dart:convert';
import 'dart:typed_data';

import 'package:bip32/bip32.dart';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final keyId = 'keyId';
  final data = Uint8List.fromList([1, 2, 3, 4]);
  final Uint8List privateKey = Uint8List.fromList([227, 35, 123, 65, 230, 94, 167, 239, 43, 209, 58, 97, 123, 14, 35, 244, 8, 115, 55, 216, 244, 132, 3, 14, 52, 56, 255, 214, 91, 83, 88, 177]);
  final Uint8List publicKey = Uint8List.fromList([154, 91, 111, 200, 105, 249, 92, 207, 158, 65, 234, 210, 123, 83, 171, 151, 40, 204, 225, 21, 100, 80, 98, 246, 210, 65, 29, 151, 214, 17, 13, 132]);

  group('Test key pair encrypt decrypt', () {
    test('ed25519', () async {

      Ed25519KeyPair ed = Ed25519KeyPair(privateKey: privateKey, keyId: keyId);

      var encrypted = await ed.encrypt(data);
      var decrypted = await ed.decrypt(encrypted);

      expect(decrypted, data);

      Uint8List chainCode = Uint8List(32); // Empty chain code (32 bytes)
      Secp256k1KeyPair secp = Secp256k1KeyPair(
        node: BIP32.fromPrivateKey(privateKey, chainCode),
        keyId: keyId
      );

      encrypted = await secp.encrypt(data);
      decrypted = await secp.decrypt(encrypted);

      expect(decrypted, data);
    });
  });
}
