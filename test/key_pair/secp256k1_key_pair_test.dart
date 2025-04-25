import 'dart:typed_data';

import 'package:bip32/bip32.dart' as bip32;
import 'package:ssi/src/key_pair/secp256k1_key_pair.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final seed = Uint8List.fromList(List.generate(32, (index) => index));
  final rootNode = bip32.BIP32.fromSeed(seed);
  final dataToSign = Uint8List.fromList([1, 2, 3, 4, 5]);
  final otherData = Uint8List.fromList([5, 4, 3, 2, 1]);

  group('Secp256k1KeyPair Tests', () {
    late Secp256k1KeyPair keyPair;

    setUp(() {
      keyPair = Secp256k1KeyPair(id: 'id', node: rootNode);
    });

    test('get publicKey should return correct type and format', () async {
      final publicKeyData = await keyPair.publicKey;
      expect(publicKeyData.type, KeyType.secp256k1);
      expect(publicKeyData.bytes, isA<Uint8List>());
      expect(publicKeyData.bytes.length, 33); // Compressed public key length
      expect(publicKeyData.bytes, equals(rootNode.publicKey));
    });

    test('get privateKey should return the correct private key', () async {
      final privateKeyBytes = await keyPair.privateKey;
      expect(privateKeyBytes, isA<Uint8List>());
      expect(privateKeyBytes.length, 32);
      expect(privateKeyBytes, equals(rootNode.privateKey));
    });

    test('supportedSignatureSchemes should return only secp256k1', () {
      final schemes = keyPair.supportedSignatureSchemes;
      expect(schemes, hasLength(1));
      expect(schemes, contains(SignatureScheme.ecdsa_secp256k1_sha256));
    });

    group('Signing and Verification', () {
      test('sign and verify should succeed with correct data and signature',
          () async {
        final signature = await keyPair.sign(dataToSign);
        expect(signature, isA<Uint8List>());
        final isValid = await keyPair.verify(dataToSign, signature);
        expect(isValid, isTrue);
      });

      test('verify should fail with incorrect signature', () async {
        final signature = await keyPair.sign(dataToSign);
        final tamperedSignature = Uint8List.fromList(signature);
        tamperedSignature[0] = tamperedSignature[0] ^ 0xFF; // Tamper the sig
        final isValid = await keyPair.verify(dataToSign, tamperedSignature);
        expect(isValid, isFalse);
      });

      test('verify should fail with different data', () async {
        final signature = await keyPair.sign(dataToSign);
        final isValid = await keyPair.verify(otherData, signature);
        expect(isValid, isFalse);
      });

      test('sign should use default scheme if none provided', () async {
        expect(() async => await keyPair.sign(dataToSign), returnsNormally);
      });

      test('verify should use default scheme if none provided', () async {
        final signature = await keyPair.sign(dataToSign);
        expect(await keyPair.verify(dataToSign, signature), isTrue);
      });

      test('sign should throw for unsupported signature scheme', () async {
        expect(
          () async => await keyPair.sign(dataToSign,
              signatureScheme: SignatureScheme.ecdsa_p256_sha256),
          throwsA(isA<SsiException>().having(
            (e) => e.code,
            'code',
            SsiExceptionType.unsupportedSignatureScheme.code,
          )),
        );
      });

      test('verify should throw for unsupported signature scheme', () async {
        final signature = await keyPair.sign(dataToSign);
        expect(
          () async => await keyPair.verify(dataToSign, signature,
              signatureScheme: SignatureScheme.ecdsa_p256_sha256),
          throwsA(isA<SsiException>().having(
            (e) => e.code,
            'code',
            SsiExceptionType.unsupportedSignatureScheme.code,
          )),
        );
      });
    });

    group('Encryption and Decryption (ECDH)', () {
      late Secp256k1KeyPair keyPairAlice;
      late Secp256k1KeyPair keyPairBob;
      final plainText = Uint8List.fromList([10, 20, 30, 40, 50]);

      setUp(() {
        // Use derived keys for Alice and Bob to ensure they are different
        final aliceNode = rootNode.derivePath("m/44'/60'/1'/0/0");
        final bobNode = rootNode.derivePath("m/44'/60'/2'/0/0");
        keyPairAlice = Secp256k1KeyPair(id: 'id1', node: aliceNode);
        keyPairBob = Secp256k1KeyPair(id: 'id2', node: bobNode);
      });

      test('encrypt and decrypt should succeed for two parties', () async {
        final alicePublicKey = await keyPairAlice.publicKey;
        final bobPublicKey = await keyPairBob.publicKey;

        // Alice encrypts for Bob
        final encryptedData = await keyPairAlice.encrypt(
          plainText,
          publicKey: bobPublicKey.bytes,
        );

        // Bob decrypts using Alice's public key
        final decryptedData = await keyPairBob.decrypt(
          encryptedData,
          publicKey: alicePublicKey.bytes,
        );

        expect(decryptedData, equals(plainText));
      });

      test('encrypt and decrypt should succeed for single party (ephemeral)',
          () async {
        // Alice encrypts for herself (implicitly using an ephemeral key)
        final encryptedData = await keyPairAlice.encrypt(plainText);

        // Alice decrypts using only her key
        final decryptedData = await keyPairAlice.decrypt(encryptedData);

        expect(decryptedData, equals(plainText));
      });

      test('decrypt should fail if wrong public key is provided (two-party)',
          () async {
        final bobPublicKey = await keyPairBob.publicKey;
        // Create a third party (Eve)
        final eveNode = rootNode.derivePath("m/44'/60'/3'/0/0");
        final keyPairEve = Secp256k1KeyPair(id: 'id', node: eveNode);
        final evePublicKey = await keyPairEve.publicKey;

        // Alice encrypts for Bob
        final encryptedData = await keyPairAlice.encrypt(
          plainText,
          publicKey: bobPublicKey.bytes,
        );

        // Bob tries to decrypt using Eve's public key instead of Alice's
        expect(
          () async => await keyPairBob.decrypt(
            encryptedData,
            publicKey: evePublicKey.bytes, // Wrong sender public key
          ),
          throwsA(isA<SsiException>().having((error) => error.code, 'code',
              SsiExceptionType.unableToDecrypt.code)),
        );
      });

      test('decrypt should fail if wrong private key is used (two-party)',
          () async {
        final alicePublicKey = await keyPairAlice.publicKey;
        final bobPublicKey = await keyPairBob.publicKey;
        // Create a third party (Eve)
        final eveNode = rootNode.derivePath("m/44'/60'/3'/0/0");
        final keyPairEve = Secp256k1KeyPair(id: 'id', node: eveNode);

        // Alice encrypts for Bob
        final encryptedData = await keyPairAlice.encrypt(
          plainText,
          publicKey: bobPublicKey.bytes,
        );

        // Eve tries to decrypt using her private key and Alice's public key
        expect(
          () async => await keyPairEve.decrypt(
            // Eve decrypting
            encryptedData,
            publicKey: alicePublicKey.bytes,
          ),
          throwsA(isA<SsiException>().having((error) => error.code, 'code',
              SsiExceptionType.unableToDecrypt.code)),
        );
      });
    });
  });
}
