import 'dart:typed_data';
import 'dart:convert';

import 'package:ssi/ssi.dart';
import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart'; // For testing invalid data
import 'package:test/test.dart';

void main() {
  final dataToSign = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
  const testKeyId1 = 'p256-key-1';
  const testKeyId2 = 'p256-key-2';
  const nonExistentKeyId = 'non-existent-key';

  group('GenericWallet Tests', () {
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
            await wallet.createKeyPair(testKeyId1, keyType: KeyType.ed25519),
        throwsArgumentError,
      );
      expect(
        () async =>
            await wallet.createKeyPair(testKeyId1, keyType: KeyType.secp256k1),
        throwsArgumentError,
      );
      expect(
        // Also test null keyType if implementation requires it explicitly
        () async => await wallet.createKeyPair(testKeyId1),
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
          jsonEncode({'type': 'ed25519', 'privateKeyHex': 'abcdef123456'}));
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
      expect(retrievedPubKey.length, 33);
    });

    test('getPublicKey should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey(nonExistentKeyId),
        throwsArgumentError,
      );
    });

    test('sign and verify should work correctly', () async {
      await wallet.createKeyPair(testKeyId1, keyType: KeyType.p256);
      await wallet.createKeyPair(testKeyId2,
          keyType: KeyType.p256); // Create a second key

      // Sign with key 1
      final signature1 = await wallet.sign(dataToSign, keyId: testKeyId1);

      // Verify with key 1 (should succeed)
      expect(
          await wallet.verify(dataToSign,
              signature: signature1, keyId: testKeyId1),
          isTrue);

      // Verify with key 2 (should fail)
      expect(
          await wallet.verify(dataToSign,
              signature: signature1, keyId: testKeyId2),
          isFalse);

      // Verify with tampered data (should fail)
      final tamperedData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      expect(
          await wallet.verify(tamperedData,
              signature: signature1, keyId: testKeyId1),
          isFalse);

      // Verify with tampered signature (should fail)
      final tamperedSignature = Uint8List.fromList(signature1);
      tamperedSignature[0] = tamperedSignature[0] ^ 0xFF; // Flip first byte
      expect(
          await wallet.verify(dataToSign,
              signature: tamperedSignature, keyId: testKeyId1),
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
