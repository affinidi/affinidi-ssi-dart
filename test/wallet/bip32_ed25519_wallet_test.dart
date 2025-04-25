import 'dart:typed_data';

import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  // Example seed (replace with a deterministic one if needed for specific vector tests)
  // IMPORTANT: Do not use this seed for production keys.
  final seed = Uint8List.fromList(List.generate(32, (index) => index + 1));
  final dataToSign = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
  const testPath1 = "m/44'/60'/0'/0'/0'";
  const testKeyId1 = 'key-44-1-0-0-0';
  const testPath2 = "m/44'/60'/0'/0'/1'";
  const nonExistentKeyId = 'non-existent-key';

  group('Bip32Ed25519Wallet', () {
    late Bip32Ed25519Wallet wallet;
    late InMemoryKeyStore keyStore;

    setUp(() async {
      keyStore = InMemoryKeyStore();
      wallet = await Bip32Ed25519Wallet.fromSeed(seed, keyStore);
    });

    test('deriveKey should derive a new Ed25519 key pair', () async {
      final newKey = await wallet.deriveKey(derivationPath: testPath1);
      expect(newKey.id, isNotNull);
      expect(newKey.id, isNotEmpty);
      expect(await wallet.hasKey(newKey.id), isTrue);
      expect(newKey.publicKey.type, KeyType.ed25519);

      final storedKey = await keyStore.get(newKey.id);
      expect(storedKey, isNotNull);
      expect(storedKey!.representation, StoredKeyRepresentation.derivationPath);
      expect(storedKey.derivationPath, testPath1);
      expect(storedKey.keyType, KeyType.ed25519);
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
      const customId = 'my-derived-ed-key';
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
            keyType: KeyType.secp256k1),
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

    test('getPublicKey should retrieve existing key pairs', () async {
      final generatedKey = await wallet.deriveKey(derivationPath: testPath1);
      final derivedKey = await wallet.getPublicKey(generatedKey.id);
      expect(derivedKey.type, KeyType.ed25519);
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
      expect(retrievedKey.bytes.length, 32); // Ed25519 public key size
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

      // Sign with derived key
      final derivedSignature = await wallet.sign(dataToSign, keyId: key1.id);
      final derivedSignature2 = await wallet.sign(dataToSign, keyId: key2.id);
      expect(
          await wallet.verify(dataToSign,
              signature: derivedSignature, keyId: key1.id),
          isTrue);

      // Verification should fail with wrong key
      expect(
          await wallet.verify(dataToSign,
              signature: derivedSignature, keyId: key2.id),
          isFalse);
      expect(
          await wallet.verify(dataToSign,
              signature: derivedSignature2, keyId: key1.id),
          isFalse);

      // Verification should fail with tampered data
      final tamperedData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      expect(
          await wallet.verify(tamperedData,
              signature: derivedSignature, keyId: key1.id),
          isFalse);

      // Verification should fail with tampered signature
      final tamperedSignature = Uint8List.fromList(derivedSignature);
      tamperedSignature[0] = tamperedSignature[0] ^ 0xFF; // Flip first byte
      expect(
          await wallet.verify(dataToSign,
              signature: tamperedSignature, keyId: key1.id),
          isFalse);
    });

    test('sign and verify should work with specific schemes', () async {
      final key = await wallet.deriveKey(derivationPath: testPath1);

      // Sign and verify with ed25519_sha256
      final sigSha256 = await wallet.sign(dataToSign,
          keyId: key.id, signatureScheme: SignatureScheme.ed25519_sha256);
      expect(
          await wallet.verify(dataToSign,
              signature: sigSha256,
              keyId: key.id,
              signatureScheme: SignatureScheme.ed25519_sha256),
          isTrue);

      // Sign and verify with eddsa_sha512
      final sigSha512 = await wallet.sign(dataToSign,
          keyId: key.id, signatureScheme: SignatureScheme.eddsa_sha512);
      expect(
          await wallet.verify(dataToSign,
              signature: sigSha512,
              keyId: key.id,
              signatureScheme: SignatureScheme.eddsa_sha512),
          isTrue);
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
      final wallet2 = await Bip32Ed25519Wallet.fromSeed(seed, keyStore2);
      final key2 =
          await wallet2.deriveKey(keyId: testKeyId1, derivationPath: testPath1);

      expect(key1.publicKey.bytes, equals(key2.publicKey.bytes));
    });

    test('Different derivation paths should produce different keys', () async {
      final key1 = await wallet.deriveKey(derivationPath: testPath1);
      final key2 = await wallet.deriveKey(derivationPath: testPath2);
      final key3 = await wallet.deriveKey(derivationPath: "m/44'/60'/1'/0'/0'");

      expect(key1.publicKey.bytes, isNot(equals(key2.publicKey.bytes)));
      expect(key1.publicKey.bytes, isNot(equals(key3.publicKey.bytes)));
      expect(key2.publicKey.bytes, isNot(equals(key3.publicKey.bytes)));
    });

    test('getSupportedSignatureSchemes should return correct schemes',
        () async {
      final key = await wallet.deriveKey(derivationPath: testPath1);
      final derivedSchemes = await wallet.getSupportedSignatureSchemes(key.id);
      expect(derivedSchemes, contains(SignatureScheme.ed25519_sha256));
      expect(derivedSchemes, contains(SignatureScheme.eddsa_sha512));
      expect(derivedSchemes.length, 2);
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

  group('Bip32Ed25519Wallet from KeyStore', () {
    late InMemoryKeyStore keyStore;

    setUp(() {
      keyStore = InMemoryKeyStore();
    });

    test('fromKeyStore successfully creates wallet', () async {
      await keyStore.setSeed(seed);
      final ksWallet = await Bip32Ed25519Wallet.fromKeyStore(keyStore);
      final key = await ksWallet.deriveKey(derivationPath: testPath1);
      expect(key.publicKey.type, KeyType.ed25519);
    });

    test('fromKeyStore throws SsiException if seed key is missing', () async {
      expect(
        () async => await Bip32Ed25519Wallet.fromKeyStore(keyStore),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          contains('Seed not found in KeyStore'),
        )),
      );
    });
  });

  group('Bip32Ed25519Wallet Encryption/Decryption', () {
    late Bip32Ed25519Wallet aliceWallet;
    late Bip32Ed25519Wallet bobWallet;
    late InMemoryKeyStore aliceKeyStore;
    late InMemoryKeyStore bobKeyStore;
    const alicePath = "m/44'/1'/0'/0'/0'";
    const bobPath = "m/44'/1'/1'/0'/0'";
    final aliceSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 10));
    final bobSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 20));
    final plainText = Uint8List.fromList([10, 20, 30, 40, 50]);
    late KeyPair aliceKey;
    late KeyPair bobKey;

    setUp(() async {
      aliceKeyStore = InMemoryKeyStore();
      bobKeyStore = InMemoryKeyStore();
      aliceWallet = await Bip32Ed25519Wallet.fromSeed(aliceSeed, aliceKeyStore);
      bobWallet = await Bip32Ed25519Wallet.fromSeed(bobSeed, bobKeyStore);
      aliceKey = await aliceWallet.deriveKey(derivationPath: alicePath);
      bobKey = await bobWallet.deriveKey(derivationPath: bobPath);
    });

    test('Two-party encrypt/decrypt should succeed', () async {
      // Get X25519 keys for ECDH
      final aliceX25519PublicKeyBytes =
          await aliceWallet.getX25519PublicKey(aliceKey.id);
      final bobX25519PublicKeyBytes =
          await bobWallet.getX25519PublicKey(bobKey.id);

      // Alice encrypts for Bob using Bob's X25519 public key
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKey.id,
        publicKey: bobX25519PublicKeyBytes, // Use Bob's X25519 key
      );

      // Bob decrypts using Alice's X25519 public key
      final decryptedData = await bobWallet.decrypt(
        encryptedData,
        keyId: bobKey.id,
        publicKey: aliceX25519PublicKeyBytes, // Use Alice's X25519 key
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
      final bobX25519PublicKeyBytes =
          await bobWallet.getX25519PublicKey(bobKey.id);

      // Generate a third party key
      final eveKeyStore = InMemoryKeyStore();
      final eveWallet = await Bip32Ed25519Wallet.fromSeed(
          Uint8List.fromList(List.generate(32, (i) => i + 30)), eveKeyStore);
      const evePath = "m/44'/1'/2'/0'/0'";
      // Generate Eve's key without ID
      final eveKey = await eveWallet.deriveKey(derivationPath: evePath);
      final eveX25519PublicKeyBytes =
          await eveWallet.getX25519PublicKey(eveKey.id);

      // Alice encrypts for Bob using Bob's X25519 public key
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKey.id,
        publicKey: bobX25519PublicKeyBytes, // Bob's X25519 key
      );

      // Bob tries to decrypt using Eve's X25519 public key instead of Alice's
      expect(
        () async => await bobWallet.decrypt(
          encryptedData,
          keyId: bobKey.id,
          publicKey:
              eveX25519PublicKeyBytes, // Wrong sender X25519 public key (Eve's)
        ),
        throwsA(isA<SsiException>().having((error) => error.code, 'code',
            SsiExceptionType.unableToDecrypt.code)),
      );
    });
  });
}
