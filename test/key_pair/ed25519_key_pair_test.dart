import 'dart:math';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  // Generate a random 32-byte seed for Ed25519
  final random = Random.secure();
  final seed =
      Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)));

  final dataToSign = Uint8List.fromList([1, 2, 3]);

  group('Test Ed25519 Key Pair', () {
    test('Ed25519 key pair should sign data and verify signature', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed: seed);
      final signature = await edKey.sign(dataToSign);
      final actual = await edKey.verify(dataToSign, signature);
      expect(actual, isTrue);
    });

    test('Verification should fail if signature is invalid', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed: seed);
      final signature = await edKey.sign(dataToSign);

      // Tamper with the signature
      final invalidSignature = Uint8List.fromList(signature);
      invalidSignature[0] =
          invalidSignature[0] ^ 0xFF; // Flip bits in the first byte

      final actual = await edKey.verify(dataToSign, invalidSignature);
      expect(actual, isFalse);
    });

    test('Verification should fail if data is different', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed: seed);
      final signature = await edKey.sign(dataToSign);

      final differentData = Uint8List.fromList([3, 2, 1]);

      final actual = await edKey.verify(differentData, signature);
      expect(actual, isFalse);
    });

    test('Ed25519 key pair properties should be correct', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed: seed);
      final publicKey = await edKey.publicKey;
      final keyType = await edKey.publicKeyType;
      final publicKeyHex = await edKey.publicKeyHex;
      final privateKeyHex = await edKey.privateKeyHex;

      expect(keyType, KeyType.ed25519);
      expect(publicKey.length, 32); // Ed25519 public key length
      expect(publicKeyHex.length, 64); // 32 bytes * 2 hex chars/byte
      expect(privateKeyHex.length, 128); // 64 bytes * 2 hex chars/byte

      // Verify getSeed returns the original seed
      expect(edKey.getSeed(), equals(seed));
    });
  });
}
