import 'dart:typed_data';

import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  // Example seed (replace with a deterministic one if needed for specific vector tests)
  // IMPORTANT: Do not use this seed for production keys.
  final seed = Uint8List.fromList(List.generate(32, (index) => index + 1));
  final dataToSign = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);

  group('Bip32Ed25519Wallet', () {
    late Bip32Ed25519Wallet wallet;

    setUp(() async {
      wallet = await Bip32Ed25519Wallet.fromSeed(seed);
    });

    test('Wallet creation from seed should contain root key', () async {
      expect(await wallet.hasKey(Bip32Ed25519Wallet.rootKeyId), isTrue);
      final rootKey = await wallet.getPublicKey(Bip32Ed25519Wallet.rootKeyId);
      expect(rootKey.type, KeyType.ed25519);
    });

    test('createKeyPair should derive a new Ed25519 key pair', () async {
      const newKeyId = '1-0';
      expect(await wallet.hasKey(newKeyId), isFalse);

      final newKey = await wallet.generateKey(keyId: newKeyId);
      expect(await wallet.hasKey(newKeyId), isTrue);
      expect(newKey.type, KeyType.ed25519);

      // Ensure creating the same key again returns the existing one
      final sameKey = await wallet.generateKey(keyId: newKeyId);
      expect(sameKey.bytes, newKey.bytes);
    });

    test('createKeyPair should throw for unsupported key type', () async {
      expect(
        () async =>
            await wallet.generateKey(keyId: '2-1', keyType: KeyType.secp256k1),
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
    });

    test('getKeyPair should retrieve existing key pairs', () async {
      const derivedKeyId = '1-2';
      await wallet.generateKey(keyId: derivedKeyId);

      final rootKey = await wallet.getPublicKey(Bip32Ed25519Wallet.rootKeyId);

      final derivedKey = await wallet.getPublicKey(derivedKeyId);
      expect(rootKey.type, KeyType.ed25519);
      expect(derivedKey.type, KeyType.ed25519);
    });

    test('getKeyPair should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey('99-99'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyPairMissingPrivateKey.code,
        )),
      );
    });

    test('getPublicKey should return the correct public key', () async {
      const derivedKeyId = '2-1';
      final derivedKey = await wallet.generateKey(keyId: derivedKeyId);

      final retrievedKey = await wallet.getPublicKey(derivedKeyId);
      expect(retrievedKey.bytes, equals(derivedKey.bytes));
      expect(retrievedKey.bytes.length, 32); // Ed25519 public key size
    });

    test('getPublicKey should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey('99-98'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyPairMissingPrivateKey.code,
        )),
      );
    });

    test('sign and verify should work for root and derived keys', () async {
      const derivedKeyId = '3-3';
      await wallet.generateKey(keyId: derivedKeyId);

      // Sign with root key
      final rootSignature =
          await wallet.sign(dataToSign, keyId: Bip32Ed25519Wallet.rootKeyId);
      expect(
          await wallet.verify(dataToSign,
              signature: rootSignature, keyId: Bip32Ed25519Wallet.rootKeyId),
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
              signature: derivedSignature, keyId: Bip32Ed25519Wallet.rootKeyId),
          isFalse);

      // Verification should fail with tampered data
      final tamperedData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      expect(
          await wallet.verify(tamperedData,
              signature: derivedSignature, keyId: derivedKeyId),
          isFalse);

      // Verification should fail with tampered signature
      final tamperedSignature = Uint8List.fromList(derivedSignature);
      tamperedSignature[0] = tamperedSignature[0] ^ 0xFF; // Flip first byte
      expect(
          await wallet.verify(dataToSign,
              signature: tamperedSignature, keyId: derivedKeyId),
          isFalse);
    });

    test('sign and verify should work with specific schemes', () async {
      const derivedKeyId = '3-4'; // Use a different ID
      await wallet.generateKey(keyId: derivedKeyId);

      // Sign and verify with ed25519_sha256
      final sigSha256 = await wallet.sign(dataToSign,
          keyId: derivedKeyId, signatureScheme: SignatureScheme.ed25519_sha256);
      expect(
          await wallet.verify(dataToSign,
              signature: sigSha256,
              keyId: derivedKeyId,
              signatureScheme: SignatureScheme.ed25519_sha256),
          isTrue);

      // Sign and verify with eddsa_sha512
      final sigSha512 = await wallet.sign(dataToSign,
          keyId: derivedKeyId, signatureScheme: SignatureScheme.eddsa_sha512);
      expect(
          await wallet.verify(dataToSign,
              signature: sigSha512,
              keyId: derivedKeyId,
              signatureScheme: SignatureScheme.eddsa_sha512),
          isTrue);
    });

    test('sign should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.sign(dataToSign, keyId: '99-97'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyPairMissingPrivateKey.code,
        )),
      );
    });

    test('verify should throw for non-existent keyId', () async {
      final rootSignature =
          await wallet.sign(dataToSign, keyId: Bip32Ed25519Wallet.rootKeyId);
      expect(
        () async => await wallet.verify(dataToSign,
            signature: rootSignature, keyId: '99-96'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyPairMissingPrivateKey.code,
        )),
      );
    });

    test('hasKey should correctly report key existence', () async {
      expect(await wallet.hasKey(Bip32Ed25519Wallet.rootKeyId), isTrue);
      expect(await wallet.hasKey('5-5'), isFalse);
      await wallet.generateKey(keyId: '5-5');
      expect(await wallet.hasKey('5-5'), isTrue);
    });

    test('Derived keys should be consistent', () async {
      const keyId = '4-2';
      final key1 = await wallet.generateKey(keyId: keyId);

      // Re-create wallet and derive same key
      final wallet2 = await Bip32Ed25519Wallet.fromSeed(seed);
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
      final rootSchemes = await wallet
          .getSupportedSignatureSchemes(Bip32Ed25519Wallet.rootKeyId);
      expect(rootSchemes, contains(SignatureScheme.ed25519_sha256));
      expect(rootSchemes, contains(SignatureScheme.eddsa_sha512));
      expect(rootSchemes.length, 2);

      // Derived key
      const derivedKeyId = '8-1';
      await wallet.generateKey(keyId: derivedKeyId);
      final derivedSchemes =
          await wallet.getSupportedSignatureSchemes(derivedKeyId);
      expect(
          derivedSchemes,
          contains(SignatureScheme
              .ed25519_sha256)); // Should still contain ed25519_sha256
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
          SsiExceptionType
              .keyPairMissingPrivateKey.code, // Matches _getKeyPair exception
        )),
      );
    });
  });

  group('Bip32Ed25519Wallet from KeyStore', () {
    late InMemoryKeyStore keyStore;

    setUp(() {
      keyStore = InMemoryKeyStore();
    });

    test('createFromKeyStore successfully creates wallet with default key',
        () async {
      await keyStore.setSeed(seed);
      final ksWallet = await Bip32Ed25519Wallet.fromKeyStore(keyStore);

      // Verify root key exists
      expect(await ksWallet.hasKey(Bip32Ed25519Wallet.rootKeyId), isTrue);
      final rootKey = await ksWallet.getPublicKey(Bip32Ed25519Wallet.rootKeyId);
      expect(rootKey.type, KeyType.ed25519);

      // Compare with wallet created directly from seed
      final directWallet = await Bip32Ed25519Wallet.fromSeed(seed);
      final directRootKey =
          await directWallet.getPublicKey(Bip32Ed25519Wallet.rootKeyId);
      expect(rootKey.bytes, directRootKey.bytes);
    });

    test('createFromKeyStore throws ArgumentError if seed key is missing',
        () async {
      expect(
        () async => await Bip32Ed25519Wallet.fromKeyStore(keyStore),
        throwsA(isA<ArgumentError>().having(
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
    const aliceKeyId = '1-1';
    const bobKeyId = '2-2';
    final aliceSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 10));
    final bobSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 20));
    final plainText = Uint8List.fromList([10, 20, 30, 40, 50]);

    setUp(() async {
      aliceWallet = await Bip32Ed25519Wallet.fromSeed(aliceSeed);
      bobWallet = await Bip32Ed25519Wallet.fromSeed(bobSeed);
      // Ensure keys are generated
      await aliceWallet.generateKey(keyId: aliceKeyId);
      await bobWallet.generateKey(keyId: bobKeyId);
    });

    test('Two-party encrypt/decrypt should succeed', () async {
      // Get X25519 keys for ECDH
      final aliceX25519PublicKeyBytes = await aliceWallet.getX25519PublicKey(aliceKeyId);
      final bobX25519PublicKeyBytes = await bobWallet.getX25519PublicKey(bobKeyId);

      // Alice encrypts for Bob using Bob's X25519 public key
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKeyId,
        publicKey: bobX25519PublicKeyBytes, // Use Bob's X25519 key
      );

      // Bob decrypts using Alice's X25519 public key
      final decryptedData = await bobWallet.decrypt(
        encryptedData,
        keyId: bobKeyId,
        publicKey: aliceX25519PublicKeyBytes, // Use Alice's X25519 key
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

    test('Decrypt should fail if wrong public key is provided (two-party)',
        () async {
      final bobX25519PublicKeyBytes = await bobWallet.getX25519PublicKey(bobKeyId);
      
      // Generate a third party key
      final eveWallet = await Bip32Ed25519Wallet.fromSeed(
          Uint8List.fromList(List.generate(32, (i) => i + 30)));
      const eveKeyId = '3-3';
      await eveWallet.generateKey(keyId: eveKeyId);
      final eveX25519PublicKeyBytes = await eveWallet.getX25519PublicKey(eveKeyId);

      // Alice encrypts for Bob using Bob's X25519 public key
      final encryptedData = await aliceWallet.encrypt(
        plainText,
        keyId: aliceKeyId,
        publicKey: bobX25519PublicKeyBytes, // Bob's X25519 key
      );

      // Bob tries to decrypt using Eve's X25519 public key instead of Alice's
      expect(
        () async => await bobWallet.decrypt(
          encryptedData,
          keyId: bobKeyId,
          publicKey: eveX25519PublicKeyBytes, // Wrong sender X25519 public key
        ),
        throwsA(isA<SsiException>().having((error) => error.code, 'code',
            SsiExceptionType.unableToDecrypt.code)),
      );
    });
  });
}
