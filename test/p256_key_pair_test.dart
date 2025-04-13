import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final dataToSign = Uint8List.fromList([1, 2, 3]);

  group('Test signature and verification', () {
    test('P-256 key pair should sign data and verify signature', () async {
      final p256key = P256KeyPair.create(keyId: "123");
      final signature = await p256key.sign(dataToSign);
      final actual = await p256key.verify(dataToSign, signature);
      expect(actual, isTrue);
    });

    test('Verification should fail if signature is invalid', () async {
      final p256key = P256KeyPair.create(keyId: "123");
      final signature = await p256key.sign(dataToSign);
      final invalidSignature = Uint8List.fromList(signature);
      invalidSignature[0]++;
      final actual = await p256key.verify(dataToSign, invalidSignature);
      expect(actual, isFalse);
    });

    test('P-256 key pair should sign data and verify signature', () async {
      final p256key = P256KeyPair.create(keyId: "123");
      final publicKey = await p256key.publicKey;
      final publicKeyHex = await p256key.publicKeyHex;
      final keyType = await p256key.publicKeyType;
      expect(keyType, KeyType.p256);
      expect(publicKey.length, 33); // Compressed P-256 key length
      expect(publicKeyHex.length, 66); // Hex representation length
    });
  });

  group('Test ECDH secret computation', () {
    test('Compute ECDH shared secret for encryption', () async {
      final keyPairAlice = P256KeyPair.create(keyId: "alice");
      final keyPairBob = P256KeyPair.create(keyId: "bob");
      final secretAlice =
          await keyPairAlice.computeEcdhSecret(await keyPairBob.publicKey);
      final secretBob =
          await keyPairBob.computeEcdhSecret(await keyPairAlice.publicKey);

      expect(secretAlice, equals(secretBob));
      expect(secretAlice.length, 32); // P-256 ECDH secret length
      expect(secretAlice, isNot(equals(Uint8List(32)))); // Ensure not all zeros
    });

    test('Compute ECDH shared secret with hex for encryption', () async {
      final keyPairAlice = P256KeyPair.create(keyId: "alice");
      final alicePublicHex = hex.encode(await keyPairAlice.publicKey);
      final keyPairBob = P256KeyPair.create(keyId: "bob");
      final bobPublicHex = hex.encode(await keyPairBob.publicKey);
      final secretAlice =
          await keyPairAlice.computeEcdhSecretFromHex(bobPublicHex);
      final secretBob =
          await keyPairBob.computeEcdhSecretFromHex(alicePublicHex);

      expect(secretAlice, equals(secretBob));
      expect(secretAlice.length, 32); // P-256 ECDH secret length
      expect(secretAlice, isNot(equals(Uint8List(32)))); // Ensure not all zeros
    });
  });
}
