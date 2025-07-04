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
    test('Ed25519 key pair should sign data and verify signature (default)',
        () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final signature = await edKey.sign(dataToSign);
      final actual = await edKey.verify(dataToSign, signature);
      expect(actual, isTrue);
    });

    test('Ed25519 key pair should sign data and verify signature', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final signature = await edKey.sign(dataToSign,
          signatureScheme: SignatureScheme.ed25519);
      final actual = await edKey.verify(dataToSign, signature,
          signatureScheme: SignatureScheme.ed25519);
      expect(actual, isTrue);
    });

    test('Verification should fail if signature is invalid (default)',
        () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final signature = await edKey.sign(dataToSign);

      // Tamper with the signature
      final invalidSignature = Uint8List.fromList(signature);
      invalidSignature[0] =
          invalidSignature[0] ^ 0xFF; // Flip bits in the first byte

      final actual = await edKey.verify(dataToSign, invalidSignature);
      expect(actual, isFalse);
    });

    test('Verification should fail if data is different (default)', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final signature = await edKey.sign(dataToSign);

      final differentData = Uint8List.fromList([3, 2, 1]);

      final actual = await edKey.verify(differentData, signature);
      expect(actual, isFalse);
    });

    test('Verification works across different supported schemes', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final sigSha = await edKey.sign(dataToSign,
          signatureScheme: SignatureScheme.ed25519);

      expect(
          await edKey.verify(dataToSign, sigSha,
              signatureScheme: SignatureScheme.ed25519),
          isTrue);
    });

    test('Ed25519 key pair properties should be correct', () {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final publicKey = edKey.publicKey;

      expect(publicKey.type, KeyType.ed25519);
      expect(publicKey.bytes.length, 32); // Ed25519 public key length

      // Verify getSeed returns the original seed
      expect(edKey.getSeed(), equals(seed));
    });

    test('KeyPair ID should match PublicKey ID', () {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final publicKey = keyPair.publicKey;
      expect(keyPair.id, equals(publicKey.id));
    });

    test('supportedSignatureSchemes should return correct schemes', () {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final schemes = edKey.supportedSignatureSchemes;
      expect(schemes, hasLength(1));
      expect(schemes, contains(SignatureScheme.ed25519));
    });
  });
}
