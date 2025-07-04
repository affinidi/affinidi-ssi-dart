import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final dataToSign = Uint8List.fromList([1, 2, 3]);

  group('Test signature and verification', () {
    test('P-521 key pair should sign data and verify signature', () async {
      final (p521key, privateKeyBytes) = P521KeyPair.generate();
      final signature = await p521key.internalSign(
          dataToSign, SignatureScheme.ecdsa_p521_sha512);
      final actual = await p521key.internalVerify(
          dataToSign, signature, SignatureScheme.ecdsa_p521_sha512);
      expect(actual, isTrue);
    });

    test('Verification should fail if signature is invalid', () async {
      final (p521key, privateKeyBytes) = P521KeyPair.generate();
      final signature = await p521key.internalSign(
          dataToSign, SignatureScheme.ecdsa_p521_sha512);
      final invalidSignature = Uint8List.fromList(signature);
      invalidSignature[0]++;
      final actual = await p521key.internalVerify(
          dataToSign, invalidSignature, SignatureScheme.ecdsa_p521_sha512);
      expect(actual, isFalse);
    });

    test('Verification should fail if data is different', () async {
      final (p521key, privateKeyBytes) = P521KeyPair.generate();
      final signature = await p521key.internalSign(
          dataToSign, SignatureScheme.ecdsa_p521_sha512);
      final differentData = Uint8List.fromList([3, 2, 1]);
      final actual = await p521key.internalVerify(
          differentData, signature, SignatureScheme.ecdsa_p521_sha512);
      expect(actual, isFalse);
    });

    test('P-521 key pair public key properties are correct', () {
      final (p521key, privateKeyBytes) = P521KeyPair.generate();
      final publicKey = p521key.publicKey;
      expect(publicKey.type, KeyType.p521);
      expect(publicKey.bytes.length, 67); // Compressed P-521 key length
    });

    test('KeyPair ID should match PublicKey ID', () {
      final (keyPair, _) = P521KeyPair.generate();
      final publicKey = keyPair.publicKey;
      expect(keyPair.id, equals(publicKey.id));
    });
  });

  group('Test ECDH secret computation', () {
    test('Compute ECDH shared secret for encryption', () async {
      final (keyPairAlice, aliceKeyBytes) = P521KeyPair.generate();
      final (keyPairBob, bobKeyBytes) = P521KeyPair.generate();
      final secretAlice =
          await keyPairAlice.computeEcdhSecret(keyPairBob.publicKey.bytes);
      final secretBob =
          await keyPairBob.computeEcdhSecret(keyPairAlice.publicKey.bytes);

      expect(secretAlice, equals(secretBob));
      expect(secretAlice.length, 66); // P-521 ECDH secret length
      expect(secretAlice, isNot(equals(Uint8List(66)))); // Ensure not all zeros
    });
  });
}
