import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final dataToSign = Uint8List.fromList([1, 2, 3]);

  group('Test signature and verification', () {
    test('P-384 key pair should sign data and verify signature', () async {
      final (p384key, privateKeyBytes) = P384KeyPair.generate();
      final signature = await p384key.sign(dataToSign);
      final actual = await p384key.verify(dataToSign, signature);
      expect(actual, isTrue);
    });

    test('Verification should fail if signature is invalid', () async {
      final (p384key, privateKeyBytes) = P384KeyPair.generate();
      final signature = await p384key.sign(dataToSign);
      final invalidSignature = Uint8List.fromList(signature);
      invalidSignature[0]++;
      final actual = await p384key.verify(dataToSign, invalidSignature);
      expect(actual, isFalse);
    });

    test('Verification should fail if data is different', () async {
      final (p384key, privateKeyBytes) = P384KeyPair.generate();
      final signature = await p384key.sign(dataToSign);
      final differentData = Uint8List.fromList([3, 2, 1]);
      final actual = await p384key.verify(differentData, signature);
      expect(actual, isFalse);
    });

    test('P-384 key pair public key properties are correct', () {
      final (p384key, privateKeyBytes) = P384KeyPair.generate();
      final publicKey = p384key.publicKey;
      expect(publicKey.type, KeyType.p384);
      expect(publicKey.bytes.length, 49); // Compressed P-384 key length
    });

    test('KeyPair ID should match PublicKey ID', () {
      final (keyPair, _) = P384KeyPair.generate();
      final publicKey = keyPair.publicKey;
      expect(keyPair.id, equals(publicKey.id));
    });
  });

  group('Test ECDH secret computation', () {
    test('Compute ECDH shared secret for encryption', () async {
      final (keyPairAlice, aliceKeyBytes) = P384KeyPair.generate();
      final (keyPairBob, bobKeyBytes) = P384KeyPair.generate();
      final secretAlice =
          await keyPairAlice.computeEcdhSecret(keyPairBob.publicKey.bytes);
      final secretBob =
          await keyPairBob.computeEcdhSecret(keyPairAlice.publicKey.bytes);

      expect(secretAlice, equals(secretBob));
      expect(secretAlice.length, 48); // P-384 ECDH secret length
      expect(secretAlice, isNot(equals(Uint8List(48)))); // Ensure not all zeros
    });
  });
}
