import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final dataToSign = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
  const nonExistentKeyId = 'non-existent-key';

  group('PersistentWallet', () {
    late PersistentWallet wallet;
    late InMemoryKeyStore keyStore;

    setUp(() {
      keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
    });

    test('createKeyPair should create a P256 key pair', () async {
      final newKey = await wallet.generateKey(keyType: KeyType.p256);
      expect(newKey.id, isNotNull);
      expect(newKey.id, isNotEmpty);
      expect(await wallet.hasKey(newKey.id), isTrue);
      expect(newKey.publicKey.type, KeyType.p256);

      final storedData = await keyStore.get(newKey.id);
      expect(storedData, isNotNull);
      expect(storedData!.keyType, KeyType.p256);
      expect(storedData.privateKeyBytes, isA<Uint8List>());
    });

    test('createKeyPair should default to P256 key pair if type is null',
        () async {
      final newKey = await wallet.generateKey();
      expect(newKey.id, isNotNull);
      expect(newKey.id, isNotEmpty);
      expect(await wallet.hasKey(newKey.id), isTrue);
      expect(newKey.publicKey.type, KeyType.p256);

      final storedData = await keyStore.get(newKey.id);
      expect(storedData, isNotNull);
      expect(storedData!.keyType, KeyType.p256);
      expect(storedData.privateKeyBytes, isA<Uint8List>());
    });

    test('createKeyPair should create an Ed25519 key pair', () async {
      final newKey = await wallet.generateKey(keyType: KeyType.ed25519);
      expect(newKey.id, isNotNull);
      expect(newKey.id, isNotEmpty);
      expect(await wallet.hasKey(newKey.id), isTrue);
      expect(newKey.publicKey.type, KeyType.ed25519);

      final storedData = await keyStore.get(newKey.id);
      expect(storedData, isNotNull);
      expect(storedData!.keyType, KeyType.ed25519);
      expect(storedData.privateKeyBytes, isA<Uint8List>());
      expect(storedData.privateKeyBytes,
          hasLength(64)); // Ed25519 private key is 64 bytes (seed + pub)
    });

    test('createKeyPair should generate a random keyId if none is provided',
        () async {
      final newKey1 = await wallet.generateKey(keyType: KeyType.p256);
      expect(newKey1.id, isNotNull);
      expect(newKey1.id, isNotEmpty);
      expect(newKey1.id.length, 32); // Check against the actual length used
      expect(await wallet.hasKey(newKey1.id), isTrue);
      expect(newKey1.publicKey.type, KeyType.p256);

      // Generate another one to ensure IDs are different
      final newKey2 = await wallet.generateKey(keyType: KeyType.ed25519);
      expect(newKey2.id, isNotNull);
      expect(newKey2.id, isNotEmpty);
      expect(newKey2.id.length, 32); // Check against the actual length used
      expect(await wallet.hasKey(newKey2.id), isTrue);
      expect(newKey1.id, isNot(equals(newKey2.id)));
    });

    test('generateKey with existing ID should return existing key', () async {
      const existingId = 'my-predefined-id';
      final firstKey =
          await wallet.generateKey(keyId: existingId, keyType: KeyType.p256);
      final secondCallKey =
          await wallet.generateKey(keyId: existingId, keyType: KeyType.p256);
      expect(secondCallKey.id, firstKey.id);
      expect(secondCallKey.publicKey.bytes, firstKey.publicKey.bytes);
    });

    test('generateKey should assign and allow retrieval by provided keyId',
        () async {
      const p256Id = 'my-custom-p256-id';
      const ed25519Id = 'my-custom-ed25519-id';

      // Test P256
      final p256KeyPair =
          await wallet.generateKey(keyId: p256Id, keyType: KeyType.p256);
      expect(p256KeyPair.id, equals(p256Id));
      expect((await wallet.getPublicKey(p256Id)).id, equals(p256Id));

      // Test Ed25519
      final edKeyPair =
          await wallet.generateKey(keyId: ed25519Id, keyType: KeyType.ed25519);
      expect(edKeyPair.id, equals(ed25519Id));
      expect((await wallet.getPublicKey(ed25519Id)).id, equals(ed25519Id));
    });

    test('createKeyPair should throw for unsupported key type', () async {
      expect(
        () async => await wallet.generateKey(keyType: KeyType.secp256k1),
        throwsArgumentError,
      );
    });

    test('getKeyPair should retrieve existing key pairs', () async {
      // P256
      final createdKey = await wallet.generateKey(keyType: KeyType.p256);
      final retrievedKeyPair = await wallet.getKeyPair(createdKey.id);
      expect(retrievedKeyPair, isNotNull);
      expect(retrievedKeyPair.id, createdKey.id);
      expect(retrievedKeyPair.publicKey.type, KeyType.p256);
      expect(retrievedKeyPair.publicKey.bytes, createdKey.publicKey.bytes);

      // Ed25519
      final createdEdKey = await wallet.generateKey(keyType: KeyType.ed25519);
      final retrievedEdKeyPair = await wallet.getKeyPair(createdEdKey.id);
      expect(retrievedEdKeyPair, isNotNull);
      expect(retrievedEdKeyPair.id, createdEdKey.id);
      expect(retrievedEdKeyPair.publicKey.type, KeyType.ed25519);
      expect(retrievedEdKeyPair.publicKey.bytes, createdEdKey.publicKey.bytes);
    });

    test('getKeyPair should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey(nonExistentKeyId),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyNotFound.code,
        )),
      );
    });

    test(
        'getKeyPair should throw for unsupported stored key type from KeyStore',
        () async {
      const unsupportedKeyId = 'unsupported-stored-key';
      // Manually insert data with unsupported type
      final unsupportedStoredKey = StoredKey(
          keyType: KeyType.secp256k1,
          privateKeyBytes: Uint8List.fromList([1, 2, 3]));
      await keyStore.set(unsupportedKeyId, unsupportedStoredKey);

      expect(
        () async => await wallet.getKeyPair(unsupportedKeyId),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.invalidKeyType.code,
        )),
      );
    });

    test('getPublicKey should return the correct public key', () async {
      final expectedKey = await wallet.generateKey(keyType: KeyType.p256);
      final retrievedKey = await wallet.getPublicKey(expectedKey.id);
      expect(retrievedKey.bytes, equals(expectedKey.publicKey.bytes));
      // P256 compressed public key size
      expect(retrievedKey.bytes.length, 33); // P256 size

      // Test Ed25519 key
      final edKey = await wallet.generateKey(keyType: KeyType.ed25519);
      final edRetrievedKey = await wallet.getPublicKey(edKey.id);
      expect(edRetrievedKey.bytes, equals(edKey.publicKey.bytes));
      expect(edRetrievedKey.bytes.length, 32); // Ed25519 public key size
    });

    test('getPublicKey should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey(nonExistentKeyId),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyNotFound.code,
        )),
      );
    });

    test('sign and verify should work correctly', () async {
      // Create keys of both types
      final p256Key = await wallet.generateKey(keyType: KeyType.p256);
      final ed25519Key = await wallet.generateKey(keyType: KeyType.ed25519);

      // Sign with key 1
      final p256Signature = await wallet.sign(dataToSign, keyId: p256Key.id);
      final ed25519Signature =
          await wallet.sign(dataToSign, keyId: ed25519Key.id);

      // Verify with key 1 (should succeed)
      expect(
          await wallet.verify(dataToSign,
              signature: p256Signature, keyId: p256Key.id),
          isTrue);
      expect(
          await wallet.verify(dataToSign,
              signature: ed25519Signature, keyId: ed25519Key.id),
          isTrue);

      // Verify with key 2 (should fail)
      // Cross-verification (P256 sig with Ed25519 key and vice-versa) should fail
      expect(
          await wallet.verify(dataToSign,
              signature: p256Signature, keyId: ed25519Key.id),
          isFalse);
      expect(
          await wallet.verify(dataToSign,
              signature: ed25519Signature, keyId: p256Key.id),
          isFalse);

      // Verify with tampered data (should fail)
      final tamperedData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      expect(
          await wallet.verify(tamperedData,
              signature: p256Signature, keyId: p256Key.id),
          isFalse);
      expect(
          await wallet.verify(tamperedData,
              signature: ed25519Signature, keyId: ed25519Key.id),
          isFalse);

      // Verify with tampered signature (should fail)
      final tamperedP256Signature = Uint8List.fromList(p256Signature);
      tamperedP256Signature[0] =
          tamperedP256Signature[0] ^ 0xFF; // Flip first byte
      expect(
          await wallet.verify(dataToSign,
              signature: tamperedP256Signature, keyId: p256Key.id),
          isFalse);

      final tamperedEd25519Signature = Uint8List.fromList(ed25519Signature);
      tamperedEd25519Signature[0] =
          tamperedEd25519Signature[0] ^ 0xFF; // Flip first byte
      expect(
          await wallet.verify(dataToSign,
              signature: tamperedEd25519Signature, keyId: ed25519Key.id),
          isFalse);
    });

    test('sign and verify should work with specific Ed25519 schemes', () async {
      // Create Ed25519 key
      final edKey = await wallet.generateKey(keyType: KeyType.ed25519);

      // Sign and verify with ed25519_sha256
      final sigSha256 = await wallet.sign(dataToSign,
          keyId: edKey.id, signatureScheme: SignatureScheme.ed25519_sha256);
      expect(
          await wallet.verify(dataToSign,
              signature: sigSha256,
              keyId: edKey.id,
              signatureScheme: SignatureScheme.ed25519_sha256),
          isTrue);

      // Sign and verify with eddsa_sha512
      final sigSha512 = await wallet.sign(dataToSign,
          keyId: edKey.id, signatureScheme: SignatureScheme.eddsa_sha512);
      expect(
          await wallet.verify(dataToSign,
              signature: sigSha512,
              keyId: edKey.id,
              signatureScheme: SignatureScheme.eddsa_sha512),
          isTrue);
    });

    test('sign should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.sign(dataToSign, keyId: nonExistentKeyId),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyNotFound.code,
        )),
      );
    });

    test('verify should throw for non-existent keyId', () async {
      final key = await wallet.generateKey(keyType: KeyType.p256);
      final signature = await wallet.sign(dataToSign, keyId: key.id);
      expect(
        () async => await wallet.verify(dataToSign,
            signature: signature, keyId: nonExistentKeyId),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyNotFound.code,
        )),
      );
    });

    test('hasKey should correctly report key existence', () async {
      final generatedKey = await wallet.generateKey(keyType: KeyType.p256);
      expect(await wallet.hasKey(generatedKey.id), isTrue);
      expect(await wallet.hasKey(nonExistentKeyId), isFalse);
    });

    test('getSupportedSignatureSchemes should return correct schemes',
        () async {
      // P256
      final p256Key = await wallet.generateKey(keyType: KeyType.p256);
      final p256Schemes = await wallet.getSupportedSignatureSchemes(p256Key.id);
      expect(p256Schemes, contains(SignatureScheme.ecdsa_p256_sha256));
      expect(p256Schemes.length, 1); // P256KeyPair only supports one

      // Ed25519
      final ed25519Key = await wallet.generateKey(keyType: KeyType.ed25519);
      final ed25519Schemes =
          await wallet.getSupportedSignatureSchemes(ed25519Key.id);
      expect(ed25519Schemes, contains(SignatureScheme.ed25519_sha256));
      expect(ed25519Schemes, contains(SignatureScheme.eddsa_sha512));
      expect(ed25519Schemes.length, 2); // Ed25519KeyPair supports two
    });

    test('getSupportedSignatureSchemes should throw for non-existent keyId',
        () async {
      expect(
        () async => await wallet.getSupportedSignatureSchemes(nonExistentKeyId),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyNotFound.code,
        )),
      );
    });

    group('getX25519PublicKey', () {
      test('should return X25519 key for an Ed25519 key', () async {
        // Generate an Ed25519 key
        final edKey = await wallet.generateKey(keyType: KeyType.ed25519);

        // Get the X25519 public key
        final x25519KeyBytes = await wallet.getX25519PublicKey(edKey.id);

        // Verify the result
        expect(x25519KeyBytes, isA<Uint8List>());
        expect(x25519KeyBytes, isNotEmpty);
        expect(x25519KeyBytes.length, 32); // X25519 public key size
      });

      test('should throw SsiException for non-existent keyId', () async {
        expect(
          () async => await wallet.getX25519PublicKey(nonExistentKeyId),
          throwsA(isA<SsiException>().having(
            (e) => e.code,
            'code',
            SsiExceptionType.keyNotFound.code,
          )), // Because _getKeyPair throws keyNotFound
        );
      });

      test('should throw SsiException for a P256 key', () async {
        // Generate a P256 key
        final p256Key = await wallet.generateKey(keyType: KeyType.p256);

        // Attempt to get X25519 key for the P256 key
        expect(
          () async => await wallet.getX25519PublicKey(p256Key.id),
          throwsA(isA<SsiException>().having(
            (e) => e.code,
            'code',
            SsiExceptionType.invalidKeyType.code,
          )),
        );
      });
    });
  });

  group('PersistentWallet Encryption/Decryption (P256)', () {
    late PersistentWallet aliceWallet;
    late PersistentWallet bobWallet;
    late PersistentWallet eveWallet;
    late InMemoryKeyStore aliceKeyStore;
    late InMemoryKeyStore bobKeyStore;
    late InMemoryKeyStore eveKeyStore;
    final plainText = Uint8List.fromList([1, 1, 2, 3, 5, 8]);
    late KeyPair aliceKey;
    late KeyPair bobKey;
    late KeyPair eveKey;

    setUp(() async {
      aliceKeyStore = InMemoryKeyStore();
      bobKeyStore = InMemoryKeyStore();
      eveKeyStore = InMemoryKeyStore();

      aliceWallet = PersistentWallet(aliceKeyStore);
      bobWallet = PersistentWallet(bobKeyStore);
      eveWallet = PersistentWallet(eveKeyStore);

      aliceKey = await aliceWallet.generateKey(keyType: KeyType.p256);
      bobKey = await bobWallet.generateKey(keyType: KeyType.p256);
      eveKey = await eveWallet.generateKey(keyType: KeyType.p256);
    });

    test('Two-party encrypt/decrypt should succeed', () async {
      // Alice encrypts for Bob using her wallet
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKey.id,
        publicKey: bobKey.publicKey.bytes,
      );

      // Bob decrypts using Alice's public key and his wallet
      final decryptedData = await bobWallet.decrypt(
        encryptedData,
        keyId: bobKey.id,
        publicKey: aliceKey.publicKey.bytes,
      );

      expect(decryptedData, equals(plainText));
    });

    test('Single-party encrypt/decrypt should succeed (no public key)',
        () async {
      // Alice encrypts for herself using her wallet
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKey.id,
        // No public key provided, implies ephemeral key usage
      );

      // Alice decrypts using only her key in her wallet
      final decryptedData = await aliceWallet.decrypt(
        encryptedData,
        keyId: aliceKey.id,
        // No public key provided
      );

      expect(decryptedData, equals(plainText));
    });

    test('Decrypt should fail if wrong public key is provided (two-party)',
        () async {
      // Alice encrypts for Bob using her wallet
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKey.id,
        publicKey: bobKey.publicKey.bytes, // Use Bob's public key bytes
      );

      // Bob tries to decrypt using Eve's public key instead of Alice's, using his wallet
      expect(
        () async => await bobWallet.decrypt(
          encryptedData,
          keyId: bobKey.id,
          publicKey: eveKey.publicKey.bytes, // Wrong sender public key (Eve's)
        ),
        throwsA(isA<SsiException>().having((error) => error.code, 'code',
            SsiExceptionType.unableToDecrypt.code)),
      );
    });
  });

  group('PersistentWallet Encryption/Decryption (Ed25519)', () {
    late PersistentWallet aliceWallet;
    late PersistentWallet bobWallet;
    late PersistentWallet eveWallet;
    late InMemoryKeyStore aliceKeyStore;
    late InMemoryKeyStore bobKeyStore;
    late InMemoryKeyStore eveKeyStore;
    final plainText = Uint8List.fromList([9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);
    late KeyPair aliceKey;
    late KeyPair bobKey;
    late KeyPair eveKey;

    setUp(() async {
      aliceKeyStore = InMemoryKeyStore();
      bobKeyStore = InMemoryKeyStore();
      eveKeyStore = InMemoryKeyStore();

      aliceWallet = PersistentWallet(aliceKeyStore);
      bobWallet = PersistentWallet(bobKeyStore);
      eveWallet = PersistentWallet(eveKeyStore);

      aliceKey = await aliceWallet.generateKey(keyType: KeyType.ed25519);
      bobKey = await bobWallet.generateKey(keyType: KeyType.ed25519);
      eveKey = await eveWallet.generateKey(keyType: KeyType.ed25519);
    });

    test('Two-party encrypt/decrypt should succeed', () async {
      final aliceX25519PublicKeyBytes =
          await aliceWallet.getX25519PublicKey(aliceKey.id);
      final bobX25519PublicKeyBytes =
          await bobWallet.getX25519PublicKey(bobKey.id);

      // Alice encrypts for Bob using her wallet and Bob's X25519 public key
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKey.id,
        publicKey: bobX25519PublicKeyBytes,
      );

      // Bob decrypts using Alice's X25519 public key and his wallet
      final decryptedData = await bobWallet.decrypt(
        encryptedData,
        keyId: bobKey.id,
        publicKey: aliceX25519PublicKeyBytes,
      );

      expect(decryptedData, equals(plainText));
    });

    test('Single-party encrypt/decrypt should succeed (no public key)',
        () async {
      // Alice encrypts for herself using her wallet
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKey.id,
      );

      // Alice decrypts using only her key in her wallet
      final decryptedData = await aliceWallet.decrypt(
        encryptedData,
        keyId: aliceKey.id,
      );

      expect(decryptedData, equals(plainText));
    });

    test('Decrypt should fail if wrong public key is provided (two-party)',
        () async {
      final bobX25519PublicKeyBytes =
          await bobWallet.getX25519PublicKey(bobKey.id);
      final eveX25519PublicKeyBytes =
          await eveWallet.getX25519PublicKey(eveKey.id);

      // Alice encrypts for Bob using her wallet and Bob's X25519 public key
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKey.id,
        publicKey: bobX25519PublicKeyBytes,
      );

      // Bob tries to decrypt using Eve's X25519 public key instead of Alice's, using his wallet
      expect(
        () async => await bobWallet.decrypt(
          encryptedData,
          keyId: bobKey.id,
          publicKey: eveX25519PublicKeyBytes,
        ),
        throwsA(isA<SsiException>().having((error) => error.code, 'code',
            SsiExceptionType.unableToDecrypt.code)),
      );
    });
  });
}
