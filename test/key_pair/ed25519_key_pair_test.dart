import 'dart:math';
import 'dart:typed_data';

import 'package:ssi/src/key_pair/ed25519_key_pair.dart';
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

    test('Ed25519 key pair should sign data and verify signature (ed25519_sha256)',
        () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final signature = await edKey.sign(dataToSign,
          signatureScheme: SignatureScheme.ed25519_sha256);
      final actual = await edKey.verify(dataToSign, signature,
          signatureScheme: SignatureScheme.ed25519_sha256);
      expect(actual, isTrue);
    });

    test('Ed25519 key pair should sign data and verify signature (eddsa_sha512)',
        () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final signature = await edKey.sign(dataToSign,
          signatureScheme: SignatureScheme.eddsa_sha512);
      final actual = await edKey.verify(dataToSign, signature,
          signatureScheme: SignatureScheme.eddsa_sha512);
      expect(actual, isTrue);
    });

    test('Verification should fail if signature is invalid (default)', () async {
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

    test('Verification should fail if wrong scheme is used', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final sigSha256 = await edKey.sign(dataToSign,
          signatureScheme: SignatureScheme.ed25519_sha256);
      final sigSha512 = await edKey.sign(dataToSign,
          signatureScheme: SignatureScheme.eddsa_sha512);

      // Verify sha256 sig with sha512 scheme
      expect(await edKey.verify(dataToSign, sigSha256,
          signatureScheme: SignatureScheme.eddsa_sha512), isFalse);
      // Verify sha512 sig with sha256 scheme
      expect(await edKey.verify(dataToSign, sigSha512,
          signatureScheme: SignatureScheme.ed25519_sha256), isFalse);
    });

    test('Ed25519 key pair properties should be correct', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final publicKey = await edKey.publicKey;

      expect(publicKey.type, KeyType.ed25519);
      expect(publicKey.bytes.length, 32); // Ed25519 public key length

      // Verify getSeed returns the original seed
      expect(edKey.getSeed(), equals(seed));
    });

    test('supportedSignatureSchemes should return correct schemes', () {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final schemes = edKey.supportedSignatureSchemes;
      expect(schemes, hasLength(2));
      expect(schemes, contains(SignatureScheme.ed25519_sha256));
      expect(schemes, contains(SignatureScheme.eddsa_sha512));
    });
  });
}
