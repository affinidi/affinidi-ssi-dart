import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  // Example seed (replace with a deterministic one if needed for specific vector tests)
  // IMPORTANT: Do not use this seed for production keys.
  final seed = Uint8List.fromList(List.generate(32, (index) => index + 1));
  final dataToSign = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
  const derivationPath1 =
      "m/44'/1'/0'/0'/0'"; // Using 1' for Ed25519 coin type example
  const derivationPath2 = "m/44'/1'/0'/0'/1'";
  const invalidDerivationPath = 'invalid-path';

  group('Bip32Ed25519Wallet', () {
    late Bip32Ed25519Wallet wallet;

    setUp(() async {
      wallet = await Bip32Ed25519Wallet.fromSeed(seed);
    });

    test('generateKey should derive a new Ed25519 key pair using keyId as path',
        () async {
      final newKey = await wallet.generateKey(keyId: derivationPath1);
      expect(newKey.id, derivationPath1);
      expect(newKey.publicKey.type, KeyType.ed25519);
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
            keyId: derivationPath1, keyType: KeyType.secp256k1),
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
            await wallet.generateKey(keyId: "44'/1'/0'/0'/0'"), // Missing 'm/'
        throwsArgumentError,
      );
    });

    test('getPublicKey should retrieve derived key pairs even if not generated',
        () async {
      final generatedKey = await wallet.generateKey(keyId: derivationPath1);
      final derivedKey1 = await wallet.getPublicKey(generatedKey.id);
      final derivedKey2 =
          await wallet.getPublicKey(derivationPath2); // Derive on demand
      expect(derivedKey1.type, KeyType.ed25519);
      expect(derivedKey1.id, generatedKey.id);
      expect(derivedKey2.type, KeyType.ed25519);
      expect(derivedKey2.id, derivationPath2);
    });

    test('getPublicKey should return the correct public key', () async {
      final derivedKey = await wallet.generateKey(keyId: derivationPath1);
      final retrievedKey = await wallet.getPublicKey(derivedKey.id);
      expect(retrievedKey.bytes, equals(derivedKey.publicKey.bytes));
      expect(retrievedKey.bytes.length, 32); // Ed25519 public key size
    });

    test('getPublicKey should throw for invalid derivation path format',
        () async {
      expect(
        () async => await wallet.getPublicKey(invalidDerivationPath),
        throwsArgumentError, // Or specific exception from HD key library
      );
    });

    test('sign and verify should work for derived keys', () async {
      final key1 = await wallet.generateKey(keyId: derivationPath1);
      final key2 = await wallet.generateKey(keyId: derivationPath2);

      // Sign with explicitly generated keys
      final signature1 = await wallet.sign(dataToSign, keyId: key1.id);
      final signature2 = await wallet.sign(dataToSign, keyId: key2.id);
      expect(
          await wallet.verify(dataToSign,
              signature: signature1, keyId: key1.id),
          isTrue);

      // Verification should fail with wrong key
      expect(
          await wallet.verify(dataToSign,
              signature: signature1, keyId: key2.id),
          isFalse);
      expect(
          await wallet.verify(dataToSign,
              signature: signature2, keyId: key1.id),
          isFalse);

      // Verification should fail with tampered data
      final tamperedData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      expect(
          await wallet.verify(tamperedData,
              signature: signature1, keyId: key1.id),
          isFalse);

      // Verification should fail with tampered signature
      final tamperedSignature = Uint8List.fromList(signature1);
      tamperedSignature[0] = tamperedSignature[0] ^ 0xFF; // Flip first byte
      expect(
          await wallet.verify(dataToSign,
              signature: tamperedSignature, keyId: key1.id),
          isFalse);

      // --- Test on-demand derivation ---
      // Sign and verify with a key derived on demand
      const onDemandPath = "m/44'/1'/2'/0'/0'";
      final signatureOnDemand =
          await wallet.sign(dataToSign, keyId: onDemandPath);
      expect(
          await wallet.verify(dataToSign,
              signature: signatureOnDemand, keyId: onDemandPath),
          isTrue);
      // Verify again, should use cache now
      expect(
          await wallet.verify(dataToSign,
              signature: signatureOnDemand, keyId: onDemandPath),
          isTrue);
      // Verify with wrong key should fail
      expect(
          await wallet.verify(dataToSign,
              signature: signatureOnDemand, keyId: derivationPath1),
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
      final wallet2 = await Bip32Ed25519Wallet.fromSeed(seed);
      // Derive the same key path
      final key2 = await wallet2
          .getPublicKey(derivationPath1); // Use getPublicKey to derive

      expect(key1.publicKey.bytes, equals(key2.bytes));
    });

    test('Derived keys should be consistent', () async {
      final key1 = await wallet.generateKey(keyId: derivationPath1);

      final wallet2 = await Bip32Ed25519Wallet.fromSeed(seed);
      final key2 = await wallet2.generateKey(keyId: derivationPath1);

      expect(key1.publicKey.bytes, equals(key2.publicKey.bytes));
    });

    test('Different derivation paths should produce different keys', () async {
      final key1 = await wallet.generateKey(keyId: derivationPath1);
      final key2 = await wallet.generateKey(keyId: derivationPath2);
      final key3 = await wallet.generateKey(
          keyId: "m/44'/1'/1'/0'/0'"); // Different path

      expect(key1.publicKey.bytes, isNot(equals(key2.publicKey.bytes)));
      expect(key1.publicKey.bytes, isNot(equals(key3.publicKey.bytes)));
      expect(key2.publicKey.bytes, isNot(equals(key3.publicKey.bytes)));
    });

    test('getSupportedSignatureSchemes should return correct schemes',
        () async {
      final key = await wallet.generateKey(keyId: derivationPath1);
      final derivedSchemes = await wallet.getSupportedSignatureSchemes(key.id);
      expect(derivedSchemes, contains(SignatureScheme.ed25519_sha256));
      expect(derivedSchemes, contains(SignatureScheme.eddsa_sha512));
      expect(derivedSchemes.length, 2);
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

  group('Bip32Ed25519Wallet from SeedStore', () {
    late InMemorySeedStore seedStore;

    setUp(() {
      seedStore = InMemorySeedStore();
    });

    test('fromSeedStore successfully creates wallet', () async {
      await seedStore.setSeed(seed);
      final ksWallet =
          await Bip32Ed25519Wallet.fromSeedStore(seedStore: seedStore);
      final key = await ksWallet.generateKey(keyId: derivationPath1);
      expect(key.publicKey.type, KeyType.ed25519);
      expect(await seedStore.getSeed(), seed);
    });

    test('fromSeedStore throws SsiException if seed key is missing', () async {
      expect(
        () async =>
            await Bip32Ed25519Wallet.fromSeedStore(seedStore: seedStore),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          contains('Seed not found in SeedStore'),
        )),
      );
    });
  });

  group('Bip32Ed25519Wallet Encryption/Decryption', () {
    late Bip32Ed25519Wallet aliceWallet;
    late Bip32Ed25519Wallet bobWallet;
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
      aliceWallet = await Bip32Ed25519Wallet.fromSeed(aliceSeed);
      bobWallet = await Bip32Ed25519Wallet.fromSeed(bobSeed);
      aliceKey = await aliceWallet.generateKey(keyId: alicePath);
      bobKey = await bobWallet.generateKey(keyId: bobPath);
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
      final eveWallet = await Bip32Ed25519Wallet.fromSeed(
          Uint8List.fromList(List.generate(32, (i) => i + 30)));
      const evePath = "m/44'/1'/2'/0'/0'";
      // Generate Eve's key
      final eveKey = await eveWallet.generateKey(keyId: evePath);
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
