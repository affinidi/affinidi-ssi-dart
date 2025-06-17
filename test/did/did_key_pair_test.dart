import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidKeyPair Tests', () {
    late Wallet wallet;
    late DidKeyManager didKeyManager;
    late DiDControllerStore keyMapping;

    setUp(() async {
      wallet = PersistentWallet(InMemoryKeyStore());
      keyMapping = DiDControllerStore();
      didKeyManager = DidKeyManager(
        keyMapping: keyMapping,
        wallet: wallet,
      );
    });

    test('should create DidKeyPair through DidController.getKey()', () async {
      // Create a verification method
      final verificationMethodId = await didKeyManager.createVerificationMethod(
        KeyType.ed25519,
      );

      // Get the DidKeyPair
      final didKeyPair = await didKeyManager.getKey(verificationMethodId);

      // Verify the DidKeyPair properties
      expect(didKeyPair.verificationMethodId, equals(verificationMethodId));
      expect(didKeyPair.walletKeyId, isNotEmpty);
      expect(didKeyPair.publicKey, isNotNull);
      expect(didKeyPair.publicKey.type, equals(KeyType.ed25519));
      expect(didKeyPair.did, startsWith('did:key:'));
      expect(didKeyPair.didDocument, isNotNull);
      expect(didKeyPair.supportedSignatureSchemes, isNotEmpty);
    });

    test('should sign and verify using DidKeyPair', () async {
      // Create a verification method
      final verificationMethodId = await didKeyManager.createVerificationMethod(
        KeyType.p256,
      );

      // Get the DidKeyPair
      final didKeyPair = await didKeyManager.getKey(verificationMethodId);

      // Test data
      final data = Uint8List.fromList('Hello, World!'.codeUnits);

      // Sign the data
      final signature = await didKeyPair.sign(data);
      expect(signature, isNotEmpty);

      // Verify the signature
      final isValid = await didKeyPair.verify(data, signature);
      expect(isValid, isTrue);

      // Verify with wrong data should fail
      final wrongData = Uint8List.fromList('Wrong data'.codeUnits);
      final isInvalid = await didKeyPair.verify(wrongData, signature);
      expect(isInvalid, isFalse);
    });

    test('should throw error when getting non-existent key', () async {
      // Try to get a key that doesn't exist
      expect(
        () => didKeyManager.getKey('non-existent-key-id'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyNotFound.code,
        )),
      );
    });

    test('should maintain proper key mapping between DID and wallet IDs',
        () async {
      // Create a verification method
      final verificationMethodId = await didKeyManager.createVerificationMethod(
        KeyType.ed25519,
      );

      // Get the DidKeyPair
      final didKeyPair = await didKeyManager.getKey(verificationMethodId);

      // Verify the mapping
      final mappedWalletKeyId = keyMapping.getWalletKeyId(verificationMethodId);
      expect(mappedWalletKeyId, equals(didKeyPair.walletKeyId));
      expect(mappedWalletKeyId, equals(didKeyPair.keyPair.id));
    });

    test('should work with existing key added via addVerificationMethod',
        () async {
      // Create a key in the wallet first
      final walletKeyId = 'test-key-123';
      await wallet.generateKey(keyId: walletKeyId, keyType: KeyType.ed25519);

      // Add it to the DID document
      final verificationMethodId = await didKeyManager.addVerificationMethod(
        KeyType.ed25519,
        walletKeyId,
      );

      // Get the DidKeyPair
      final didKeyPair = await didKeyManager.getKey(verificationMethodId);

      // Verify it references the same wallet key
      expect(didKeyPair.walletKeyId, equals(walletKeyId));
      expect(didKeyPair.keyPair.id, equals(walletKeyId));
      expect(didKeyPair.publicKey.type, equals(KeyType.ed25519));
    });
  });
}
