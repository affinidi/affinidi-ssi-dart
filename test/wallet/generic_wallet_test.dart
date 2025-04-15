import 'dart:typed_data';
import 'dart:convert';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final dataToSign = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
  const testKeyId1 = 'p256-key-1';
  const testEd25519KeyId1 = 'ed25519-key-1';
  const nonExistentKeyId = 'non-existent-key';

  group('GenericWallet', () {
    late GenericWallet wallet;
    late InMemoryKeyStore keyStore; // Use specific type for direct manipulation

    setUp(() {
      keyStore = InMemoryKeyStore();
      wallet = GenericWallet(keyStore);
    });

    test('createKeyPair should create a P256 key pair', () async {
      expect(await wallet.hasKey(testKeyId1), isFalse);

      final newKeyPair =
          await wallet.createKeyPair(testKeyId1, keyType: KeyType.p256);
      expect(await wallet.hasKey(testKeyId1), isTrue);
      expect(await newKeyPair.id, testKeyId1);
      expect(await newKeyPair.publicKeyType, KeyType.p256);

      // Check if key is actually stored
      final storedData = await keyStore.get(testKeyId1);
      expect(storedData, isNotNull);
      final decodedData = jsonDecode(storedData!);
      expect(decodedData['type'], KeyType.p256.name);
      expect(decodedData['privateKeyHex'], isA<String>());
    });

    test('createKeyPair should default to P256 key pair if type is null',
        () async {
      const defaultKeyId = 'default-key';
      expect(await wallet.hasKey(defaultKeyId), isFalse);

      // Call without specifying keyType
      final newKeyPair = await wallet.createKeyPair(defaultKeyId);
      expect(await wallet.hasKey(defaultKeyId), isTrue);
      expect(await newKeyPair.id, defaultKeyId);
      expect(await newKeyPair.publicKeyType,
          KeyType.p256); // Should default to P256

      // Check storage
      final storedData = await keyStore.get(defaultKeyId);
      expect(storedData, isNotNull);
      final decodedData = jsonDecode(storedData!);
      expect(decodedData['type'], KeyType.p256.name);
    });

    test('createKeyPair should create an Ed25519 key pair', () async {
      expect(await wallet.hasKey(testEd25519KeyId1), isFalse);

      final newKeyPair = await wallet.createKeyPair(testEd25519KeyId1,
          keyType: KeyType.ed25519);
      expect(await wallet.hasKey(testEd25519KeyId1), isTrue);
      expect(await newKeyPair.id, testEd25519KeyId1);
      expect(await newKeyPair.publicKeyType, KeyType.ed25519);

      // Check if key is actually stored
      final storedData = await keyStore.get(testEd25519KeyId1);
      expect(storedData, isNotNull);
      final decodedData = jsonDecode(storedData!);
      expect(decodedData['type'], KeyType.ed25519.name);
      expect(decodedData['privateKeyHex'], isA<String>());
      // Ensure stored hex decodes to 64 bytes (Ed25519 private+public key size)
      expect(hex.decode(decodedData['privateKeyHex']), hasLength(64));
    });

    test('createKeyPair should throw for existing keyId', () async {
      await wallet.createKeyPair(testKeyId1,
          keyType: KeyType.p256); // Create first
      expect(
        () async =>
            await wallet.createKeyPair(testKeyId1, keyType: KeyType.p256),
        throwsArgumentError,
      );
    });

    test('createKeyPair should throw for unsupported key type', () async {
      expect(
        () async =>
            await wallet.createKeyPair(testKeyId1, keyType: KeyType.secp256k1),
        throwsArgumentError,
      );
      expect(
        () async =>
            await wallet.createKeyPair(testKeyId1, keyType: KeyType.rsa),
        throwsArgumentError,
      );
    });

    test('getKeyPair should retrieve existing P256 key pair', () async {
      final createdKeyPair =
          await wallet.createKeyPair(testKeyId1, keyType: KeyType.p256);
      final retrievedKeyPair = await wallet.getKeyPair(testKeyId1);

      expect(await retrievedKeyPair.id, testKeyId1);
      expect(await retrievedKeyPair.publicKeyType, KeyType.p256);
      // Compare public keys to ensure it's the same key material
      expect(await retrievedKeyPair.publicKey, await createdKeyPair.publicKey);
    });

    test('getKeyPair should retrieve existing Ed25519 key pair', () async {
      final createdKeyPair = await wallet.createKeyPair(testEd25519KeyId1,
          keyType: KeyType.ed25519);
      final retrievedKeyPair = await wallet.getKeyPair(testEd25519KeyId1);

      expect(await retrievedKeyPair.id, testEd25519KeyId1);
      expect(await retrievedKeyPair.publicKeyType, KeyType.ed25519);
      // Compare public keys to ensure it's the same key material
      expect(await retrievedKeyPair.publicKey, await createdKeyPair.publicKey);
    });

    test('getKeyPair should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getKeyPair(nonExistentKeyId),
        throwsArgumentError,
      );
    });

    test('getKeyPair should throw for invalid stored data (missing type)',
        () async {
      // Manually insert invalid data
      await keyStore.set(
          testKeyId1, jsonEncode({'privateKeyHex': 'abcdef123456'}));
      expect(
        () async => await wallet.getKeyPair(testKeyId1),
        throwsArgumentError,
      );
    });

    test('getKeyPair should throw for invalid stored data (missing key)',
        () async {
      // Manually insert invalid data
      await keyStore.set(testKeyId1, jsonEncode({'type': 'p256'}));
      expect(
        () async => await wallet.getKeyPair(testKeyId1),
        throwsArgumentError,
      );
    });

    test('getKeyPair should throw for unsupported stored key type', () async {
      // Manually insert data with unsupported type
      await keyStore.set(testKeyId1,
          jsonEncode({'type': 'secp256k1', 'privateKeyHex': 'abcdef123456'}));
      expect(
        () async => await wallet.getKeyPair(testKeyId1),
        throwsArgumentError,
      );
    });

    test('getPublicKey should return the correct public key', () async {
      final keyPair =
          await wallet.createKeyPair(testKeyId1, keyType: KeyType.p256);
      final expectedPubKey = await keyPair.publicKey;

      final retrievedPubKey = await wallet.getPublicKey(testKeyId1);
      expect(retrievedPubKey, equals(expectedPubKey));
      // P256 compressed public key size
      expect(retrievedPubKey.length, 33); // P256 size

      // Test Ed25519 key
      final edKeyPair = await wallet.createKeyPair(testEd25519KeyId1,
          keyType: KeyType.ed25519);
      final edExpectedPubKey = await edKeyPair.publicKey;
      final edRetrievedPubKey = await wallet.getPublicKey(testEd25519KeyId1);
      expect(edRetrievedPubKey, equals(edExpectedPubKey));
      expect(edRetrievedPubKey.length, 32); // Ed25519 public key size
    });

    test('getPublicKey should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey(nonExistentKeyId),
        throwsArgumentError,
      );
    });

    test('sign and verify should work correctly', () async {
      // Create keys of both types
      await wallet.createKeyPair(testKeyId1, keyType: KeyType.p256);
      await wallet.createKeyPair(testEd25519KeyId1, keyType: KeyType.ed25519);

      // Sign with key 1
      final p256Signature = await wallet.sign(dataToSign, keyId: testKeyId1);
      final ed25519Signature =
          await wallet.sign(dataToSign, keyId: testEd25519KeyId1);

      // Verify with key 1 (should succeed)
      expect(
          await wallet.verify(dataToSign,
              signature: p256Signature, keyId: testKeyId1),
          isTrue);
      expect(
          await wallet.verify(dataToSign,
              signature: ed25519Signature, keyId: testEd25519KeyId1),
          isTrue);

      // Verify with key 2 (should fail)
      // Cross-verification (P256 sig with Ed25519 key and vice-versa) should fail
      expect(
          await wallet.verify(dataToSign,
              signature: p256Signature, keyId: testEd25519KeyId1),
          isFalse);
      expect(
          await wallet.verify(dataToSign,
              signature: ed25519Signature, keyId: testKeyId1),
          isFalse);

      // Verify with tampered data (should fail)
      final tamperedData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      expect(
          await wallet.verify(tamperedData,
              signature: p256Signature, keyId: testKeyId1),
          isFalse);
      expect(
          await wallet.verify(tamperedData,
              signature: ed25519Signature, keyId: testEd25519KeyId1),
          isFalse);

      // Verify with tampered signature (should fail)
      final tamperedP256Signature = Uint8List.fromList(p256Signature);
      tamperedP256Signature[0] =
          tamperedP256Signature[0] ^ 0xFF; // Flip first byte
      expect(
          await wallet.verify(dataToSign,
              signature: tamperedP256Signature, keyId: testKeyId1),
          isFalse);

      final tamperedEd25519Signature = Uint8List.fromList(ed25519Signature);
      tamperedEd25519Signature[0] =
          tamperedEd25519Signature[0] ^ 0xFF; // Flip first byte
      expect(
          await wallet.verify(dataToSign,
              signature: tamperedEd25519Signature, keyId: testEd25519KeyId1),
          isFalse);
    });

    test('sign should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.sign(dataToSign, keyId: nonExistentKeyId),
        throwsArgumentError,
      );
    });

    test('verify should throw for non-existent keyId', () async {
      // Need a valid signature first
      final keyPair =
          await wallet.createKeyPair(testKeyId1, keyType: KeyType.p256);
      final signature = await keyPair.sign(dataToSign);

      expect(
        () async => await wallet.verify(dataToSign,
            signature: signature, keyId: nonExistentKeyId),
        throwsArgumentError,
      );
    });

    test('hasKey should correctly report key existence', () async {
      expect(await wallet.hasKey(testKeyId1), isFalse);
      await wallet.createKeyPair(testKeyId1, keyType: KeyType.p256);
      expect(await wallet.hasKey(testKeyId1), isTrue);
      expect(await wallet.hasKey(nonExistentKeyId), isFalse);
    });
  });
}
