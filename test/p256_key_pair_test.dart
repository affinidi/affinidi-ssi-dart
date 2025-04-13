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
      final publicKey = p256key.publicKey;
      // TODO: check if public key matches a p256 key
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

      // TODO: assert that secrets are the same
      // TODO: check if secret makes sense
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

      // TODO: assert that secrets are the same
      // TODO: check if secret makes sense
    });
  });
}
