import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final dataToSign = Uint8List.fromList([1, 2, 3]);

  group('Test signature and verification', () {
    test('P-256 key pair should sign data and verify signature', () async {
      final p256key = P256KeyPair();
      final signature = await p256key.sign(dataToSign);
      final actual = await p256key.verify(dataToSign, signature);
      expect(actual, isTrue);
    });

    test('Verification should fail if signature is invalid', () async {
      final p256key = P256KeyPair();
      final signature = await p256key.sign(dataToSign);
      final invalidSignature = Uint8List.fromList(signature);
      invalidSignature[0]++;
      final actual = await p256key.verify(dataToSign, invalidSignature);
      expect(actual, isFalse);
    });

    test('Verification should fail if data is different', () async {
      final p256key = P256KeyPair();
      final signature = await p256key.sign(dataToSign);

      final differentData = Uint8List.fromList([3, 2, 1]);

      final actual = await p256key.verify(differentData, signature);
      expect(actual, isFalse);
    });

    test('P-256 key pair should sign data and verify signature', () async {
      final p256key = P256KeyPair();
      final publicKey = p256key.publicKey;
      expect(publicKey.type, KeyType.p256);
      expect(publicKey.bytes.length, 33); // Compressed P-256 key length
    });
  });

  group('Test ECDH secret computation', () {
    test('Compute ECDH shared secret for encryption', () async {
      final keyPairAlice = P256KeyPair();
      final keyPairBob = P256KeyPair();
      final secretAlice = await keyPairAlice
          .computeEcdhSecret((await keyPairBob.publicKey).bytes);
      final secretBob = await keyPairBob
          .computeEcdhSecret((await keyPairAlice.publicKey).bytes);

      expect(secretAlice, equals(secretBob));
      expect(secretAlice.length, 32); // P-256 ECDH secret length
      expect(secretAlice, isNot(equals(Uint8List(32)))); // Ensure not all zeros
    });
  });
}
