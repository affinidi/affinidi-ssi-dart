import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  // Example seed (replace with a deterministic one if needed for specific vector tests)
  // IMPORTANT: Do not use this seed for production keys.
  final seed = Uint8List.fromList(List.generate(32, (index) => index + 1));
  final dataToSign = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
  const testPath1 = "m/44'/60'/0'/0/0";
  const testKeyId1 = 'key-44-60-0-0-0';
  const testPath2 = "m/44'/60'/0'/0/1";
  const nonExistentKeyId = 'non-existent-key';

  group('Bip32Wallet (Secp256k1)', () {
    late Bip32Wallet wallet;
    late InMemoryKeyStore keyStore;

    setUp(() async {
      keyStore = InMemoryKeyStore();
      wallet = await Bip32Wallet.fromSeed(seed, keyStore);
    });

    test('deriveKey should derive a new Secp256k1 key pair', () async {
      final newKey = await wallet.deriveKey(derivationPath: testPath1);
      expect(newKey.id, isNotNull);
      expect(newKey.id, isNotEmpty);
      expect(await wallet.hasKey(newKey.id), isTrue);
      expect(newKey.publicKey.type, KeyType.secp256k1);

      final storedKey = await keyStore.get(newKey.id);
      expect(storedKey, isNotNull);
      expect(storedKey!.representation, StoredKeyRepresentation.derivationPath);
      expect(storedKey.derivationPath, testPath1);
      expect(storedKey.keyType, KeyType.secp256k1);
    });

    test(
        'deriveKey with existing ID and matching path should return existing key',
        () async {
      final firstKey =
          await wallet.deriveKey(keyId: testKeyId1, derivationPath: testPath1);
      expect(await wallet.hasKey(testKeyId1), isTrue);

      final sameKey =
          await wallet.deriveKey(keyId: testKeyId1, derivationPath: testPath1);
      expect(sameKey.publicKey.bytes, firstKey.publicKey.bytes);
      expect(sameKey.id, firstKey.id);
      expect(sameKey.publicKey.type, firstKey.publicKey.type);
    });

    test('deriveKey should assign and allow retrieval by provided keyId',
        () async {
      const customId = 'my-derived-secp-key';
      final keyPair =
          await wallet.deriveKey(keyId: customId, derivationPath: testPath1);
      expect(keyPair.id, equals(customId));
      expect((await wallet.getPublicKey(customId)).id, equals(customId));
    });

    test('deriveKey with existing ID and different path should throw',
        () async {
      await wallet.deriveKey(keyId: testKeyId1, derivationPath: testPath1);
      expect(
        () async => await wallet.deriveKey(
            keyId: testKeyId1, derivationPath: testPath2),
        throwsArgumentError,
      );
    });

    test('deriveKey should throw for unsupported key type', () async {
      expect(
        () async => await wallet.deriveKey(
            keyId: testKeyId1,
            derivationPath: testPath1,
            keyType: KeyType.ed25519),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.invalidKeyType.code,
        )),
      );
    });

    test('generateKey should throw for hd wallets', () async {
      expect(
        () async => await wallet.generateKey(keyId: testKeyId1),
        throwsUnsupportedError,
      );
    });

    test('deriveKey should throw if derivationPath is invalid', () async {
      expect(
        () async => await wallet.deriveKey(
            keyId: testKeyId1,
            derivationPath: "44'/60'/0'/0/0"), // Missing 'm/'
        throwsArgumentError,
      );
    });

    test('getPublicKey should retrieve existing key pairs', () async {
      final generatedKey = await wallet.deriveKey(derivationPath: testPath1);
      final derivedKey = await wallet.getPublicKey(generatedKey.id);
      expect(derivedKey.type, KeyType.secp256k1);
      expect(derivedKey.id, generatedKey.id);
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

    test('getPublicKey should return the correct public key', () async {
      final derivedKey = await wallet.deriveKey(derivationPath: testPath1);
      final retrievedKey = await wallet.getPublicKey(derivedKey.id);
      expect(retrievedKey.bytes, equals(derivedKey.publicKey.bytes));
      expect(retrievedKey.bytes.length, 33);
    });

    test('getPublicKey should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey('99-98'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyNotFound.code,
        )),
      );
    });

    test('sign and verify should work for derived keys', () async {
      final key1 = await wallet.deriveKey(derivationPath: testPath1);
      final key2 = await wallet.deriveKey(derivationPath: testPath2);

      final derivedSignature = await wallet.sign(dataToSign, keyId: key1.id);
      expect(
          await wallet.verify(dataToSign,
              signature: derivedSignature, keyId: key1.id),
          isTrue);

      // Verification should fail with wrong key
      expect(
          await wallet.verify(dataToSign,
              signature: derivedSignature, keyId: key2.id), // Use key2's ID
          isFalse);

      // Verification should fail with tampered data
      final tamperedData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      expect(
          await wallet.verify(tamperedData,
              signature: derivedSignature, keyId: key1.id),
          isFalse);

      // Verification should fail with tampered signature
      final tamperedSignature = Uint8List.fromList(derivedSignature);
      tamperedSignature[0] = tamperedSignature[0] ^ 0xFF;
      expect(
          await wallet.verify(dataToSign,
              signature: tamperedSignature, keyId: key1.id),
          isFalse);
    });

    test('sign should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.sign(dataToSign, keyId: '99-97'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyNotFound.code,
        )),
      );
    });

    test('verify should throw for non-existent keyId', () async {
      final key = await wallet.deriveKey(derivationPath: testPath1);
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
      final generatedKey = await wallet.deriveKey(derivationPath: testPath1);
      expect(await wallet.hasKey(generatedKey.id), isTrue);
      expect(await wallet.hasKey(nonExistentKeyId), isFalse);
    });

    test('Derived keys should be consistent', () async {
      final key1 =
          await wallet.deriveKey(keyId: testKeyId1, derivationPath: testPath1);

      final keyStore2 = InMemoryKeyStore();
      final wallet2 = await Bip32Wallet.fromSeed(seed, keyStore2);
      final key2 =
          await wallet2.deriveKey(keyId: testKeyId1, derivationPath: testPath1);

      expect(key1.publicKey.bytes, equals(key2.publicKey.bytes));
    });

    test('Different derivation paths should produce different keys', () async {
      final key1 = await wallet.deriveKey(derivationPath: testPath1);
      final key2 = await wallet.deriveKey(derivationPath: testPath2);
      final key3 = await wallet.deriveKey(derivationPath: "m/44'/60'/1'/0/0");

      expect(key1.publicKey.bytes, isNot(equals(key2.publicKey.bytes)));
      expect(key1.publicKey.bytes, isNot(equals(key3.publicKey.bytes)));
      expect(key2.publicKey.bytes, isNot(equals(key3.publicKey.bytes)));
    });

    test('getSupportedSignatureSchemes should return correct schemes',
        () async {
      final key = await wallet.deriveKey(derivationPath: testPath1);
      final derivedSchemes = await wallet.getSupportedSignatureSchemes(key.id);
      expect(derivedSchemes, contains(SignatureScheme.ecdsa_secp256k1_sha256));
      expect(derivedSchemes.length, 1);
    });

    test('getSupportedSignatureSchemes should throw for non-existent keyId',
        () async {
      expect(
        () async => await wallet.getSupportedSignatureSchemes('99-95'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyNotFound.code,
        )),
      );
    });
  });

  group('Bip32Wallet (Secp256k1) from KeyStore', () {
    late InMemoryKeyStore keyStore;

    setUp(() {
      keyStore = InMemoryKeyStore();
    });

    test('fromKeyStore successfully creates wallet', () async {
      await keyStore.setSeed(seed);
      final ksWallet = await Bip32Wallet.fromKeyStore(keyStore);
      final key = await ksWallet.deriveKey(derivationPath: testPath1);
      expect(key.publicKey.type, KeyType.secp256k1);
    });

    test('fromKeyStore throws SsiException if seed key is missing', () async {
      expect(
        () async => await Bip32Wallet.fromKeyStore(keyStore),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          contains('Seed not found in KeyStore'),
        )),
      );
    });
  });

  group('Bip32Wallet (Secp256k1) Encryption/Decryption', () {
    late Bip32Wallet aliceWallet;
    late Bip32Wallet bobWallet;
    late InMemoryKeyStore aliceKeyStore;
    late InMemoryKeyStore bobKeyStore;
    const alicePath = "m/44'/60'/0'/0/0";
    const bobPath = "m/44'/60'/1'/0/0";
    final aliceSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 30));
    final bobSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 40));
    final plainText = Uint8List.fromList([11, 22, 33, 44, 55]);
    late KeyPair aliceKey;
    late KeyPair bobKey;

    setUp(() async {
      aliceKeyStore = InMemoryKeyStore();
      bobKeyStore = InMemoryKeyStore();
      aliceWallet = await Bip32Wallet.fromSeed(aliceSeed, aliceKeyStore);
      bobWallet = await Bip32Wallet.fromSeed(bobSeed, bobKeyStore);
      aliceKey = await aliceWallet.deriveKey(derivationPath: alicePath);
      bobKey = await bobWallet.deriveKey(derivationPath: bobPath);
    });

    test('Two-party encrypt/decrypt should succeed', () async {
      // Alice encrypts for Bob
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKey.id,
        publicKey: bobKey.publicKey.bytes, // Use Bob's public key bytes
      );

      // Bob decrypts using Alice's public key
      final decryptedData = await bobWallet.decrypt(
        encryptedData,
        keyId: bobKey.id,
        publicKey: aliceKey.publicKey.bytes, // Use Alice's public key bytes
      );

      expect(decryptedData, equals(plainText));
    });

    test('Single-party encrypt/decrypt should succeed (no public key)',
        () async {
      // Alice encrypts for herself
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKey.id,
        // No public key provided, implies ephemeral key usage
      );

      // Alice decrypts using only her key
      final decryptedData = await aliceWallet.decrypt(
        encryptedData,
        keyId: aliceKey.id,
        // No public key provided
      );

      expect(decryptedData, equals(plainText));
    });

    test('Decrypt should fail if wrong public key is provided (two-party)',
        () async {
      // Generate a third party key
      final eveKeyStore = InMemoryKeyStore();
      final eveWallet = await Bip32Wallet.fromSeed(
          Uint8List.fromList(List.generate(32, (i) => i + 50)), eveKeyStore);
      const evePath = "m/44'/60'/2'/0/0";
      // Generate Eve's key without ID
      final eveKey = await eveWallet.deriveKey(derivationPath: evePath);

      // Alice encrypts for Bob
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKey.id,
        publicKey: bobKey.publicKey.bytes, // Use Bob's public key bytes
      );

      // Bob tries to decrypt using Eve's public key instead of Alice's
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
}
