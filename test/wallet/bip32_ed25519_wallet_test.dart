import 'dart:typed_data';

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
      final rootKeyPair = await wallet.getKeyPair(Bip32Ed25519Wallet.rootKeyId);
      expect(await rootKeyPair.id, Bip32Ed25519Wallet.rootKeyId);
      expect(await rootKeyPair.publicKeyType, KeyType.ed25519);
    });

    test('createKeyPair should derive a new Ed25519 key pair', () async {
      const newKeyId = '1-0';
      expect(await wallet.hasKey(newKeyId), isFalse);

      final newKeyPair = await wallet.createKeyPair(newKeyId);
      expect(await wallet.hasKey(newKeyId), isTrue);
      expect(await newKeyPair.id, newKeyId);
      expect(await newKeyPair.publicKeyType, KeyType.ed25519);

      // Ensure creating the same key again returns the existing one
      final sameKeyPair = await wallet.createKeyPair(newKeyId);
      expect(await sameKeyPair.publicKey, await newKeyPair.publicKey);
      expect(await sameKeyPair.id, await newKeyPair.id);
    });

    test('createKeyPair should throw for unsupported key type', () async {
      expect(
        () async =>
            await wallet.createKeyPair('2-1', keyType: KeyType.secp256k1),
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
          SsiExceptionType.other.code, // Based on current implementation
        )),
      );
      expect(
        () async => await wallet.createKeyPair('1'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.other.code, // Based on current implementation
        )),
      );
      expect(
        () async => await wallet.createKeyPair('1-'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.other.code, // Based on current implementation
        )),
      );
    });

    test('getKeyPair should retrieve existing key pairs', () async {
      const derivedKeyId = '1-2';
      await wallet.createKeyPair(derivedKeyId);

      final rootKeyPair = await wallet.getKeyPair(Bip32Ed25519Wallet.rootKeyId);
      expect(await rootKeyPair.id, Bip32Ed25519Wallet.rootKeyId);

      final derivedKeyPair = await wallet.getKeyPair(derivedKeyId);
      expect(await derivedKeyPair.id, derivedKeyId);
    });

    test('getKeyPair should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getKeyPair('99-99'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType
              .keyPairMissingPrivateKey.code, // Based on implementation
        )),
      );
    });

    test('getPublicKey should return the correct public key', () async {
      const derivedKeyId = '2-1';
      final derivedKeyPair = await wallet.createKeyPair(derivedKeyId);
      final expectedPubKey = await derivedKeyPair.publicKey;

      final retrievedPubKey = await wallet.getPublicKey(derivedKeyId);
      expect(retrievedPubKey, equals(expectedPubKey));
      expect(retrievedPubKey.length, 32); // Ed25519 public key size
    });

    test('getPublicKey should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.getPublicKey('99-98'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType
              .keyPairMissingPrivateKey.code, // Based on implementation
        )),
      );
    });

    test('sign and verify should work for root and derived keys', () async {
      const derivedKeyId = '3-3';
      await wallet.createKeyPair(derivedKeyId);

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

    test('sign should throw for non-existent keyId', () async {
      expect(
        () async => await wallet.sign(dataToSign, keyId: '99-97'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType
              .keyPairMissingPrivateKey.code, // Based on implementation
        )),
      );
    });

    test('verify should throw for non-existent keyId', () async {
      // Need a valid signature first
      final rootSignature =
          await wallet.sign(dataToSign, keyId: Bip32Ed25519Wallet.rootKeyId);
      expect(
        () async => await wallet.verify(dataToSign,
            signature: rootSignature, keyId: '99-96'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType
              .keyPairMissingPrivateKey.code, // Based on implementation
        )),
      );
    });

    test('hasKey should correctly report key existence', () async {
      expect(await wallet.hasKey(Bip32Ed25519Wallet.rootKeyId), isTrue);
      expect(await wallet.hasKey('5-5'), isFalse);
      await wallet.createKeyPair('5-5');
      expect(await wallet.hasKey('5-5'), isTrue);
    });

    test('Derived keys should be consistent', () async {
      const keyId = '4-2';
      final keyPair1 = await wallet.createKeyPair(keyId);
      final pubKey1 = await keyPair1.publicKey;

      // Re-create wallet and derive same key
      final wallet2 = await Bip32Ed25519Wallet.fromSeed(seed);
      final keyPair2 = await wallet2.createKeyPair(keyId);
      final pubKey2 = await keyPair2.publicKey;

      expect(pubKey1, equals(pubKey2));
    });

    test('Different derivation paths should produce different keys', () async {
      const keyId1 = '6-1';
      const keyId2 = '6-2'; // Same account, different key index
      const keyId3 = '7-1'; // Different account

      final keyPair1 = await wallet.createKeyPair(keyId1);
      final keyPair2 = await wallet.createKeyPair(keyId2);
      final keyPair3 = await wallet.createKeyPair(keyId3);

      final pubKey1 = await keyPair1.publicKey;
      final pubKey2 = await keyPair2.publicKey;
      final pubKey3 = await keyPair3.publicKey;

      expect(pubKey1, isNot(equals(pubKey2)));
      expect(pubKey1, isNot(equals(pubKey3)));
      expect(pubKey2, isNot(equals(pubKey3)));
    });
  });
}
