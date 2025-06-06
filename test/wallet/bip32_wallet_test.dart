import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  // Example seed (replace with a deterministic one if needed for specific vector tests)
  // IMPORTANT: Do not use this seed for production keys.
  final seed = Uint8List.fromList(List.generate(32, (index) => index + 1));
  final dataToSign = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
  const derivationPath1 = "m/44'/60'/0'/0/0";
  const derivationPath2 = "m/44'/60'/0'/0/1";
  const invalidDerivationPath = 'invalid-path';

  group('Bip32Wallet (Secp256k1)', () {
    late Bip32Wallet wallet;

    setUp(() async {
      wallet = Bip32Wallet.fromSeed(seed);
    });

    test(
        'generateKey should derive a new Secp256k1 key pair using keyId as path',
        () async {
      final newKey = await wallet.generateKey(keyId: derivationPath1);
      expect(newKey.id, derivationPath1);
      expect(newKey.publicKey.type, KeyType.secp256k1);
    });

    test('generateKey with existing path should return cached key', () async {
      final firstKey = await wallet.generateKey(keyId: derivationPath1);

      final sameKey = await wallet.generateKey(keyId: derivationPath1);
      expect(sameKey.publicKey.bytes, firstKey.publicKey.bytes);
      expect(sameKey.id, firstKey.id);
      expect(sameKey.publicKey.type, firstKey.publicKey.type);
    });

    test('generateKey should throw for unsupported key type', () async {
      expect(
        () async => await wallet.generateKey(
            keyId: derivationPath1, keyType: KeyType.ed25519),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.invalidKeyType.code,
        )),
      );
    });

    test('generateKey should throw if keyId (derivationPath) is null',
        () async {
      expect(
        () async => await wallet.generateKey(keyId: null),
        throwsArgumentError,
      );
    });

    test('generateKey should throw if keyId (derivationPath) is invalid format',
        () async {
      expect(
        () async =>
            await wallet.generateKey(keyId: "44'/60'/0'/0/0"), // Missing 'm/'
        throwsArgumentError,
      );
    });

    test('getPublicKey should retrieve derived key pairs even if not generated',
        () async {
      final generatedKey = await wallet.generateKey(keyId: derivationPath1);
      final derivedKey1 = await wallet.getPublicKey(generatedKey.id);
      final derivedKey2 = await wallet.getPublicKey(derivationPath2);
      expect(derivedKey1.type, KeyType.secp256k1);
      expect(derivedKey1.id, generatedKey.id);
      expect(derivedKey2.type, KeyType.secp256k1);
      expect(derivedKey2.id, derivationPath2);
    });

    test('getPublicKey should return the correct public key', () async {
      final derivedKey = await wallet.generateKey(keyId: derivationPath1);
      final retrievedKey = await wallet.getPublicKey(derivedKey.id);
      expect(retrievedKey.bytes, equals(derivedKey.publicKey.bytes));
      expect(retrievedKey.bytes.length, 33);
    });

    test('getPublicKey should throw for invalid derivation path format',
        () async {
      expect(
        () async => await wallet.getPublicKey(invalidDerivationPath),
        throwsArgumentError,
      );
    });

    test('sign and verify should work for derived keys', () async {
      final key1 = await wallet.generateKey(keyId: derivationPath1);
      final key2 = await wallet.generateKey(keyId: derivationPath2);

      // Sign with explicitly generated key
      final signature1 = await wallet.sign(dataToSign, keyId: key1.id);
      expect(
          await wallet.verify(dataToSign,
              signature: signature1, keyId: key1.id),
          isTrue);

      // Verification should fail with wrong key
      expect(
          await wallet.verify(dataToSign,
              signature: signature1, keyId: key2.id), // Use key2's ID
          isFalse);

      // --- Test on-demand derivation ---
      // Verification should fail with tampered data
      final tamperedData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      expect(
          await wallet.verify(tamperedData,
              signature: signature1, keyId: key1.id),
          isFalse);

      // Verification should fail with tampered signature
      final tamperedSignature = Uint8List.fromList(signature1);
      tamperedSignature[0] = tamperedSignature[0] ^ 0xFF;
      expect(
          await wallet.verify(dataToSign,
              signature: tamperedSignature, keyId: key1.id),
          isFalse);
    });

    test('sign/verify should throw for invalid derivation path format',
        () async {
      expect(
          () async =>
              await wallet.sign(dataToSign, keyId: invalidDerivationPath),
          throwsArgumentError);
      // Need a valid signature to test verify's path check
      final validSig = await wallet.sign(dataToSign, keyId: derivationPath1);
      expect(
          () async => await wallet.verify(dataToSign,
              signature: validSig, keyId: invalidDerivationPath),
          throwsArgumentError);
    });

    test('Derived keys should be consistent', () async {
      final key1 = await wallet.generateKey(keyId: derivationPath1);

      // Create a new wallet instance with the same seed
      final wallet2 = Bip32Wallet.fromSeed(seed);
      // Derive the same key path
      final key2 = await wallet2.getPublicKey(derivationPath1);

      expect(key1.publicKey.bytes, equals(key2.bytes));
    });

    test('Derived keys should be consistent', () async {
      final key1 = await wallet.generateKey(keyId: derivationPath1);

      final wallet2 = Bip32Wallet.fromSeed(seed);
      final key2 = await wallet2.generateKey(keyId: derivationPath1);

      expect(key1.publicKey.bytes, equals(key2.publicKey.bytes));
    });

    test('Different derivation paths should produce different keys', () async {
      final key1 = await wallet.generateKey(keyId: derivationPath1);
      final key2 = await wallet.generateKey(keyId: derivationPath2);
      final key3 = await wallet.generateKey(keyId: "m/44'/60'/1'/0/0");

      expect(key1.publicKey.bytes, isNot(equals(key2.publicKey.bytes)));
      expect(key1.publicKey.bytes, isNot(equals(key3.publicKey.bytes)));
      expect(key2.publicKey.bytes, isNot(equals(key3.publicKey.bytes)));
    });

    test('getSupportedSignatureSchemes should return correct schemes',
        () async {
      final key = await wallet.generateKey(keyId: derivationPath1);
      final derivedSchemes = await wallet.getSupportedSignatureSchemes(key.id);
      expect(derivedSchemes, contains(SignatureScheme.ecdsa_secp256k1_sha256));
      expect(derivedSchemes.length, 1);
    });

    test(
        'getSupportedSignatureSchemes should throw for invalid derivation path format',
        () async {
      expect(
        () async =>
            await wallet.getSupportedSignatureSchemes(invalidDerivationPath),
        throwsArgumentError,
      );
    });
  });

  group('Bip32Wallet (Secp256k1) Encryption/Decryption', () {
    late Bip32Wallet aliceWallet;
    late Bip32Wallet bobWallet;
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
      aliceWallet = Bip32Wallet.fromSeed(aliceSeed);
      bobWallet = Bip32Wallet.fromSeed(bobSeed);
      aliceKey = await aliceWallet.generateKey(keyId: alicePath);
      bobKey = await bobWallet.generateKey(keyId: bobPath);
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
      final eveWallet = Bip32Wallet.fromSeed(
          Uint8List.fromList(List.generate(32, (i) => i + 50)));
      const evePath = "m/44'/60'/2'/0/0";
      // Generate Eve's key
      final eveKey = await eveWallet.generateKey(keyId: evePath);

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
