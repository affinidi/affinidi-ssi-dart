import 'dart:typed_data';

import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  // Example seed (replace with a deterministic one if needed for specific vector tests)
  // IMPORTANT: Do not use this seed for production keys.
  final seed = Uint8List.fromList(List.generate(32, (index) => index + 1));
  final dataToSign = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);

  group('Bip32Wallet (Secp256k1)', () {
    late Bip32Wallet wallet;

    setUp(() {
      wallet = Bip32Wallet.fromSeed(seed);
    });

    test('Wallet creation from seed should contain root key', () async {
      expect(await wallet.hasKey(Bip32Wallet.rootKeyId), isTrue);
      final rootKey = await wallet.getPublicKey(Bip32Wallet.rootKeyId);
      expect(rootKey.type, KeyType.secp256k1);
    });

    test('createKeyPair should derive a new Secp256k1 key pair', () async {
      const newKeyId = '1-0'; // Account 1, Key 0
      expect(await wallet.hasKey(newKeyId), isFalse);

      final newKey = await wallet.generateKey(keyId: newKeyId);
      expect(await wallet.hasKey(newKeyId), isTrue);
      expect(newKey.type, KeyType.secp256k1);

      // Ensure creating the same key again returns the existing one
      final sameKey = await wallet.generateKey(keyId: newKeyId);
      expect(sameKey.bytes, newKey.bytes);
    });

    test('createKeyPair should throw for unsupported key type', () async {
      expect(
        () async =>
            await wallet.generateKey(keyId: '2-1', keyType: KeyType.ed25519),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.invalidKeyType.code,
        )),
      );
    });

    test('createKeyPair should throw for invalid keyId format', () async {
      expect(
        () async => await wallet.generateKey(keyId: 'invalid-id'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.other.code,
        )),
      );
      expect(
        () async => await wallet.generateKey(keyId: '1'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.other.code,
        )),
      );
      expect(
        () async => await wallet.generateKey(keyId: '1-'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.other.code,
        )),
      );
      expect(
        () async => await wallet.generateKey(keyId: '-1'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.other.code,
        )),
      );
    });

    test('getKeyPair should retrieve existing key pairs', () async {
      const derivedKeyId = '1-2';
      await wallet.generateKey(keyId: derivedKeyId);

      final rootKey = await wallet.getPublicKey(Bip32Wallet.rootKeyId);
      expect(rootKey.type, KeyType.secp256k1);

      final derivedKey = await wallet.getPublicKey(derivedKeyId);
      expect(derivedKey.type, KeyType.secp256k1);
    });

    test('getKeyPair should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey('99-99'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.invalidKeyType.code,
        )),
      );
    });

    test('getPublicKey should return the correct public key', () async {
      const derivedKeyId = '2-1';
      final derivedKey = await wallet.generateKey(keyId: derivedKeyId);
      final retrievedKey = await wallet.getPublicKey(derivedKeyId);
      expect(retrievedKey.bytes, equals(derivedKey.bytes));
      // Secp256k1 compressed public key size
      expect(retrievedKey.bytes.length, 33);
    });

    test('getPublicKey should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey('99-98'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.invalidKeyType.code,
        )),
      );
    });

    test('sign and verify should work for root and derived keys', () async {
      const derivedKeyId = '3-3';
      await wallet.generateKey(keyId: derivedKeyId);

      // Sign with root key
      final rootSignature =
          await wallet.sign(dataToSign, keyId: Bip32Wallet.rootKeyId);
      expect(
          await wallet.verify(dataToSign,
              signature: rootSignature, keyId: Bip32Wallet.rootKeyId),
          isTrue);

      // Sign with derived key
      final derivedSignature =
          await wallet.sign(dataToSign, keyId: derivedKeyId);
      expect(
          await wallet.verify(dataToSign,
              signature: derivedSignature, keyId: derivedKeyId),
          isTrue);

      // Verification should fail with wrong key
      expect(
          await wallet.verify(dataToSign,
              signature: rootSignature, keyId: derivedKeyId),
          isFalse);
      expect(
          await wallet.verify(dataToSign,
              signature: derivedSignature, keyId: Bip32Wallet.rootKeyId),
          isFalse);

      // Verification should fail with tampered data
      final tamperedData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      expect(
          await wallet.verify(tamperedData,
              signature: derivedSignature, keyId: derivedKeyId),
          isFalse);

      // Verification should fail with tampered signature
      final tamperedSignature = Uint8List.fromList(derivedSignature);
      tamperedSignature[0] = tamperedSignature[0] ^ 0xFF;
      expect(
          await wallet.verify(dataToSign,
              signature: tamperedSignature, keyId: derivedKeyId),
          isFalse);
    });

    test('sign should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.sign(dataToSign, keyId: '99-97'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.invalidKeyType.code,
        )),
      );
    });

    test('verify should throw for non-existent keyId', () async {
      final rootSignature =
          await wallet.sign(dataToSign, keyId: Bip32Wallet.rootKeyId);
      expect(
        () async => await wallet.verify(dataToSign,
            signature: rootSignature, keyId: '99-96'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.invalidKeyType.code,
        )),
      );
    });

    test('hasKey should correctly report key existence', () async {
      expect(await wallet.hasKey(Bip32Wallet.rootKeyId), isTrue);
      expect(await wallet.hasKey('5-5'), isFalse);
      await wallet.generateKey(keyId: '5-5');
      expect(await wallet.hasKey('5-5'), isTrue);
    });

    test('Derived keys should be consistent', () async {
      const keyId = '4-2';
      final key1 = await wallet.generateKey(keyId: keyId);

      // Re-create wallet and derive same key
      final wallet2 = Bip32Wallet.fromSeed(seed);
      final key2 = await wallet2.generateKey(keyId: keyId);

      expect(key1.bytes, equals(key2.bytes));
    });

    test('Different derivation paths should produce different keys', () async {
      const keyId1 = '6-1';
      const keyId2 = '6-2'; // Same account, different key index
      const keyId3 = '7-1'; // Different account

      final key1 = await wallet.generateKey(keyId: keyId1);
      final key2 = await wallet.generateKey(keyId: keyId2);
      final key3 = await wallet.generateKey(keyId: keyId3);

      expect(key1.bytes, isNot(equals(key2.bytes)));
      expect(key1.bytes, isNot(equals(key3.bytes)));
      expect(key2.bytes, isNot(equals(key3.bytes)));
    });

    test('getSupportedSignatureSchemes should return correct schemes',
        () async {
      // Root key
      final rootSchemes =
          await wallet.getSupportedSignatureSchemes(Bip32Wallet.rootKeyId);
      expect(rootSchemes, contains(SignatureScheme.ecdsa_secp256k1_sha256));
      expect(rootSchemes.length, 1);

      // Derived key
      const derivedKeyId = '8-1';
      await wallet.generateKey(keyId: derivedKeyId);
      final derivedSchemes =
          await wallet.getSupportedSignatureSchemes(derivedKeyId);
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
          SsiExceptionType.invalidKeyType.code, // Matches _getKeyPair exception
        )),
      );
    });
  });

  group('Bip32Wallet (Secp256k1) from KeyStore', () {
    late InMemoryKeyStore keyStore;

    setUp(() {
      keyStore = InMemoryKeyStore();
    });

    test('createFromKeyStore successfully creates wallet with default key',
        () async {
      await keyStore.setSeed(seed);
      final ksWallet = await Bip32Wallet.fromKeyStore(keyStore);
      expect(await ksWallet.hasKey(Bip32Wallet.rootKeyId), isTrue);
      final rootKey = await ksWallet.getPublicKey(Bip32Wallet.rootKeyId);
      expect(rootKey.type, KeyType.secp256k1);

      // Compare with wallet created directly from seed
      final directWallet = Bip32Wallet.fromSeed(seed);
      final directRootKey =
          await directWallet.getPublicKey(Bip32Wallet.rootKeyId);
      expect(rootKey.bytes, directRootKey.bytes);
    });

    test('createFromKeyStore throws ArgumentError if seed key is missing',
        () async {
      expect(
        () async => await Bip32Wallet.fromKeyStore(keyStore),
        throwsA(isA<ArgumentError>().having(
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
    const aliceKeyId = '1-1';
    const bobKeyId = '2-2';
    final aliceSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 30));
    final bobSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 40));
    final plainText = Uint8List.fromList([11, 22, 33, 44, 55]);

    setUp(() async {
      aliceWallet = Bip32Wallet.fromSeed(aliceSeed);
      bobWallet = Bip32Wallet.fromSeed(bobSeed);
      // Ensure keys are generated
      await aliceWallet.generateKey(keyId: aliceKeyId);
      await bobWallet.generateKey(keyId: bobKeyId);
    });

    test('Two-party encrypt/decrypt should succeed', () async {
      final alicePublicKey = await aliceWallet.getPublicKey(aliceKeyId);
      final bobPublicKey = await bobWallet.getPublicKey(bobKeyId);

      // Alice encrypts for Bob
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKeyId,
        publicKey: bobPublicKey.bytes,
      );

      // Bob decrypts using Alice's public key
      final decryptedData = await bobWallet.decrypt(
        encryptedData,
        keyId: bobKeyId,
        publicKey: alicePublicKey.bytes,
      );

      expect(decryptedData, equals(plainText));
    });

    test('Single-party encrypt/decrypt should succeed (no public key)',
        () async {
      // Alice encrypts for herself
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKeyId,
        // No public key provided, implies ephemeral key usage
      );

      // Alice decrypts using only her key
      final decryptedData = await aliceWallet.decrypt(
        encryptedData,
        keyId: aliceKeyId,
        // No public key provided
      );

      expect(decryptedData, equals(plainText));
    });

    test('Decrypt should fail with wrong key', () async {
      final bobPublicKey = await bobWallet.getPublicKey(bobKeyId);

      // Alice encrypts for Bob
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKeyId,
        publicKey: bobPublicKey.bytes,
      );

      // Alice tries to decrypt with her own key (should fail)
      expect(
        () async => await aliceWallet.decrypt(
          encryptedData,
          keyId: aliceKeyId, // Wrong private key for decryption
          publicKey:
              bobPublicKey.bytes, // Bob's public key (sender in this context)
        ),
        throwsA(isA<SsiException>().having((error) => error.code, 'code',
            SsiExceptionType.unableToDecrypt.code)),
      );
    });

    test('Decrypt should fail if wrong public key is provided (two-party)',
        () async {
      final bobPublicKey = await bobWallet.getPublicKey(bobKeyId);
      // Generate a third party key
      final eveWallet = Bip32Wallet.fromSeed(
          Uint8List.fromList(List.generate(32, (i) => i + 50)));
      await eveWallet.generateKey(keyId: '3-3');
      final evePublicKey = await eveWallet.getPublicKey('3-3');

      // Alice encrypts for Bob
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKeyId,
        publicKey: bobPublicKey.bytes,
      );

      // Bob tries to decrypt using Eve's public key instead of Alice's
      expect(
        () async => await bobWallet.decrypt(
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
