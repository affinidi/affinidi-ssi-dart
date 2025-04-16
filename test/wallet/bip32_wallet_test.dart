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

      final newKey = await wallet.createKeyPair(newKeyId);
      expect(await wallet.hasKey(newKeyId), isTrue);
      expect(newKey.type, KeyType.secp256k1);

      // Ensure creating the same key again returns the existing one
      final sameKey = await wallet.createKeyPair(newKeyId);
      expect(sameKey.bytes, newKey.bytes);
    });

    test('createKeyPair should throw for unsupported key type', () async {
      expect(
        () async => await wallet.createKeyPair('2-1', keyType: KeyType.ed25519),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.invalidKeyType.code,
        )),
      );
    });

    test('createKeyPair should throw for invalid keyId format', () async {
      expect(
        () async => await wallet.createKeyPair('invalid-id'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.other.code,
        )),
      );
      expect(
        () async => await wallet.createKeyPair('1'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.other.code,
        )),
      );
      expect(
        () async => await wallet.createKeyPair('1-'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.other.code,
        )),
      );
      expect(
        () async => await wallet.createKeyPair('-1'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.other.code,
        )),
      );
    });

    test('getKeyPair should retrieve existing key pairs', () async {
      const derivedKeyId = '1-2';
      await wallet.createKeyPair(derivedKeyId);

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
      final derivedKey = await wallet.createKeyPair(derivedKeyId);
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
      await wallet.createKeyPair(derivedKeyId);

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
      await wallet.createKeyPair('5-5');
      expect(await wallet.hasKey('5-5'), isTrue);
    });

    test('Derived keys should be consistent', () async {
      const keyId = '4-2';
      final key1 = await wallet.createKeyPair(keyId);

      // Re-create wallet and derive same key
      final wallet2 = Bip32Wallet.fromSeed(seed);
      final key2 = await wallet2.createKeyPair(keyId);

      expect(key1.bytes, equals(key2.bytes));
    });

    test('Different derivation paths should produce different keys', () async {
      const keyId1 = '6-1';
      const keyId2 = '6-2'; // Same account, different key index
      const keyId3 = '7-1'; // Different account

      final key1 = await wallet.createKeyPair(keyId1);
      final key2 = await wallet.createKeyPair(keyId2);
      final key3 = await wallet.createKeyPair(keyId3);

      expect(key1.bytes, isNot(equals(key2.bytes)));
      expect(key1.bytes, isNot(equals(key3.bytes)));
      expect(key2.bytes, isNot(equals(key3.bytes)));
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
      final ksWallet = await Bip32Wallet.createFromKeyStore(keyStore);
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
        () async => await Bip32Wallet.createFromKeyStore(keyStore),
        throwsA(isA<ArgumentError>().having(
          (e) => e.message,
          'message',
          contains('Seed not found in KeyStore'),
        )),
      );
    });
  });
}
