import 'dart:typed_data';

import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/src/wallet/key_store/stored_key.dart';
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

      final newKey =
          await wallet.generateKey(keyId: testKeyId1, keyType: KeyType.p256);
      expect(await wallet.hasKey(testKeyId1), isTrue);
      expect(newKey.type, KeyType.p256);

      // Check if key is actually stored
      final storedData = await keyStore.get(testKeyId1);
      expect(storedData, isNotNull);
      expect(storedData!.type, KeyType.p256);
      expect(storedData.key, isA<Uint8List>());
    });

    test('createKeyPair should default to P256 key pair if type is null',
        () async {
      const defaultKeyId = 'default-key';
      expect(await wallet.hasKey(defaultKeyId), isFalse);

      // Call without specifying keyType
      final newKey = await wallet.generateKey(keyId: defaultKeyId);
      expect(await wallet.hasKey(defaultKeyId), isTrue);
      expect(newKey.type, KeyType.p256);

      // Check storage
      final storedData = await keyStore.get(defaultKeyId);
      expect(storedData, isNotNull);
      expect(storedData!.type, KeyType.p256);
      expect(storedData.key, isA<Uint8List>());
    });

    test('createKeyPair should create an Ed25519 key pair', () async {
      expect(await wallet.hasKey(testEd25519KeyId1), isFalse);

      final newKey = await wallet.generateKey(
          keyId: testEd25519KeyId1, keyType: KeyType.ed25519);
      expect(await wallet.hasKey(testEd25519KeyId1), isTrue);
      expect(newKey.type, KeyType.ed25519);

      // Check if key is actually stored
      final storedData = await keyStore.get(testEd25519KeyId1);
      expect(storedData, isNotNull);
      expect(storedData!.type, KeyType.ed25519);
      expect(storedData.key, isA<Uint8List>());
      // Ensure stored key has the correct length (32 bytes for Ed25519 seed/private key)
      expect(storedData.key, hasLength(64));
    });

    test('createKeyPair should generate a random keyId if none is provided',
        () async {
      // Call without specifying keyId
      final newKey1 = await wallet.generateKey(keyType: KeyType.p256);
      expect(newKey1.id, isNotNull);
      expect(newKey1.id, isNotEmpty);
      expect(newKey1.id.length, GenericWallet.randomIdLength);
      expect(await wallet.hasKey(newKey1.id), isTrue);
      expect(newKey1.type, KeyType.p256);

      // Generate another one to ensure IDs are different
      final newKey2 = await wallet.generateKey(keyType: KeyType.ed25519);
      expect(newKey2.id, isNotNull);
      expect(newKey2.id, isNotEmpty);
      expect(newKey2.id.length, GenericWallet.randomIdLength);
      expect(await wallet.hasKey(newKey2.id), isTrue);
      expect(newKey1.id, isNot(equals(newKey2.id)));
    });

    test('createKeyPair should throw for existing keyId', () async {
      await wallet.generateKey(keyId: testKeyId1, keyType: KeyType.p256);
      expect(
        () async =>
            await wallet.generateKey(keyId: testKeyId1, keyType: KeyType.p256),
        throwsArgumentError,
      );
    });

    test('createKeyPair should throw for unsupported key type', () async {
      expect(
        () async => await wallet.generateKey(
            keyId: testKeyId1, keyType: KeyType.secp256k1),
        throwsArgumentError,
      );
      expect(
        () async =>
            await wallet.generateKey(keyId: testKeyId1, keyType: KeyType.rsa),
        throwsArgumentError,
      );
    });

    test('getKeyPair should retrieve existing P256 key pair', () async {
      final createdKey =
          await wallet.generateKey(keyId: testKeyId1, keyType: KeyType.p256);
      final retrievedKey = await wallet.getPublicKey(testKeyId1);

      expect(retrievedKey.type, KeyType.p256);
      expect(retrievedKey.bytes, createdKey.bytes);
    });

    test('getKeyPair should retrieve existing Ed25519 key pair', () async {
      final createdKey = await wallet.generateKey(
          keyId: testEd25519KeyId1, keyType: KeyType.ed25519);
      final retrievedKey = await wallet.getPublicKey(testEd25519KeyId1);

      expect(retrievedKey.type, KeyType.ed25519);
      expect(retrievedKey.bytes, createdKey.bytes);
    });

    test('getKeyPair should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey(nonExistentKeyId),
        throwsArgumentError,
      );
    });

    test('getKeyPair should throw for unsupported stored key type', () async {
      // Manually insert data with unsupported type
      final unsupportedKey = StoredKey(
        type: KeyType.secp256k1, // Unsupported by GenericWallet
        key: Uint8List.fromList([1, 2, 3]), // Dummy key data
      );
      await keyStore.set(testKeyId1, unsupportedKey);

      // Expect ArgumentError because _getKeyPair finds an unsupported type
      expect(
        () async => await wallet.getPublicKey(testKeyId1),
        throwsArgumentError,
      );
    });

    test('getPublicKey should return the correct public key', () async {
      final expectedKey =
          await wallet.generateKey(keyId: testKeyId1, keyType: KeyType.p256);

      final retrievedKey = await wallet.getPublicKey(testKeyId1);
      expect(retrievedKey.bytes, equals(expectedKey.bytes));
      // P256 compressed public key size
      expect(retrievedKey.bytes.length, 33); // P256 size

      // Test Ed25519 key
      final edKey = await wallet.generateKey(
          keyId: testEd25519KeyId1, keyType: KeyType.ed25519);
      final edRetrievedKey = await wallet.getPublicKey(testEd25519KeyId1);
      expect(edRetrievedKey.bytes, equals(edKey.bytes));
      expect(edRetrievedKey.bytes.length, 32); // Ed25519 public key size
    });

    test('getPublicKey should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey(nonExistentKeyId),
        throwsArgumentError,
      );
    });

    test('sign and verify should work correctly', () async {
      // Create keys of both types
      await wallet.generateKey(keyId: testKeyId1, keyType: KeyType.p256);
      await wallet.generateKey(
          keyId: testEd25519KeyId1, keyType: KeyType.ed25519);

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

    test('sign and verify should work with specific Ed25519 schemes', () async {
      // Create Ed25519 key
      await wallet.generateKey(
          keyId: testEd25519KeyId1, keyType: KeyType.ed25519);

      // Sign and verify with ed25519_sha256
      final sigSha256 = await wallet.sign(dataToSign,
          keyId: testEd25519KeyId1,
          signatureScheme: SignatureScheme.ed25519_sha256);
      expect(
          await wallet.verify(dataToSign,
              signature: sigSha256,
              keyId: testEd25519KeyId1,
              signatureScheme: SignatureScheme.ed25519_sha256),
          isTrue);

      // Sign and verify with eddsa_sha512
      final sigSha512 = await wallet.sign(dataToSign,
          keyId: testEd25519KeyId1,
          signatureScheme: SignatureScheme.eddsa_sha512);
      expect(
          await wallet.verify(dataToSign,
              signature: sigSha512,
              keyId: testEd25519KeyId1,
              signatureScheme: SignatureScheme.eddsa_sha512),
          isTrue);
    });

    test('sign should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.sign(dataToSign, keyId: nonExistentKeyId),
        throwsArgumentError,
      );
    });

    test('verify should throw for non-existent keyId', () async {
      await wallet.generateKey(keyId: testKeyId1, keyType: KeyType.p256);
      final signature = await wallet.sign(dataToSign, keyId: testKeyId1);

      expect(
        () async => await wallet.verify(dataToSign,
            signature: signature, keyId: nonExistentKeyId),
        throwsArgumentError,
      );
    });

    test('hasKey should correctly report key existence', () async {
      expect(await wallet.hasKey(testKeyId1), isFalse);
      await wallet.generateKey(keyId: testKeyId1, keyType: KeyType.p256);
      expect(await wallet.hasKey(testKeyId1), isTrue);
      expect(await wallet.hasKey(nonExistentKeyId), isFalse);
    });

    test('getSupportedSignatureSchemes should return correct schemes',
        () async {
      // P256
      await wallet.generateKey(keyId: testKeyId1, keyType: KeyType.p256);
      final p256Schemes = await wallet.getSupportedSignatureSchemes(testKeyId1);
      expect(p256Schemes, contains(SignatureScheme.ecdsa_p256_sha256));
      expect(p256Schemes.length, 1); // P256KeyPair only supports one

      // Ed25519
      await wallet.generateKey(
          keyId: testEd25519KeyId1, keyType: KeyType.ed25519);
      final ed25519Schemes =
          await wallet.getSupportedSignatureSchemes(testEd25519KeyId1);
      expect(ed25519Schemes, contains(SignatureScheme.ed25519_sha256));
      expect(ed25519Schemes, contains(SignatureScheme.eddsa_sha512));
      expect(ed25519Schemes.length, 2); // Ed25519KeyPair supports two
    });

    test('getSupportedSignatureSchemes should throw for non-existent keyId',
        () async {
      expect(
        () async => await wallet.getSupportedSignatureSchemes(nonExistentKeyId),
        throwsArgumentError,
      );
    });
  });

  group('GenericWallet Encryption/Decryption (P256)', () {
    late GenericWallet aliceWallet;
    late GenericWallet bobWallet;
    late GenericWallet eveWallet; // Added for Eve
    late InMemoryKeyStore aliceKeyStore;
    late InMemoryKeyStore bobKeyStore;
    late InMemoryKeyStore eveKeyStore; // Added for Eve
    const aliceKeyId = 'alice-p256-key';
    const bobKeyId = 'bob-p256-key';
    const eveKeyId = 'eve-p256-key'; // Added for Eve
    final plainText = Uint8List.fromList([1, 1, 2, 3, 5, 8]);

    setUp(() async {
      // Initialize separate key stores and wallets
      aliceKeyStore = InMemoryKeyStore();
      bobKeyStore = InMemoryKeyStore();
      eveKeyStore = InMemoryKeyStore(); // Initialize Eve's store

      aliceWallet = GenericWallet(aliceKeyStore);
      bobWallet = GenericWallet(bobKeyStore);
      eveWallet = GenericWallet(eveKeyStore); // Initialize Eve's wallet

      // Ensure keys are generated in their respective wallets
      await aliceWallet.generateKey(keyId: aliceKeyId, keyType: KeyType.p256);
      await bobWallet.generateKey(keyId: bobKeyId, keyType: KeyType.p256);
      // Generate Eve's key in her wallet for the failure test
      await eveWallet.generateKey(keyId: eveKeyId, keyType: KeyType.p256);
    });

    test('Two-party encrypt/decrypt should succeed', () async {
      // Get keys from respective wallets
      final alicePublicKey = await aliceWallet.getPublicKey(aliceKeyId);
      final bobPublicKey = await bobWallet.getPublicKey(bobKeyId);

      // Alice encrypts for Bob using her wallet
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKeyId,
        publicKey: bobPublicKey.bytes,
      );

      // Bob decrypts using Alice's public key and his wallet
      final decryptedData = await bobWallet.decrypt(
        encryptedData,
        keyId: bobKeyId,
        publicKey: alicePublicKey.bytes,
      );

      expect(decryptedData, equals(plainText));
    });

    test('Single-party encrypt/decrypt should succeed (no public key)',
        () async {
      // Alice encrypts for herself using her wallet
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKeyId,
        // No public key provided, implies ephemeral key usage
      );

      // Alice decrypts using only her key in her wallet
      final decryptedData = await aliceWallet.decrypt(
        encryptedData,
        keyId: aliceKeyId,
        // No public key provided
      );

      expect(decryptedData, equals(plainText));
    });

    test('Decrypt should fail if wrong public key is provided (two-party)',
        () async {
      final bobPublicKey = await bobWallet.getPublicKey(bobKeyId);
      final evePublicKey = await eveWallet
          .getPublicKey(eveKeyId); // Get Eve's key from her wallet

      // Alice encrypts for Bob using her wallet
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKeyId,
        publicKey: bobPublicKey.bytes,
      );

      // Bob tries to decrypt using Eve's public key instead of Alice's, using his wallet
      expect(
        () async => await bobWallet.decrypt(
          // Use bobWallet here
          encryptedData,
          keyId: bobKeyId,
          publicKey: evePublicKey.bytes, // Wrong sender public key
        ),
        throwsA(isA<SsiException>().having((error) => error.code, 'code',
            SsiExceptionType.unableToDecrypt.code)),
      );
    });
  });
}
