import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidKeyPair Tests', () {
    late Wallet wallet;
    late DidKeyController didKeyController;
    late DiDControllerStore keyMapping;

    setUp(() async {
      wallet = PersistentWallet(InMemoryKeyStore());
      keyMapping = DefaultDiDControllerStore();
      didKeyController = DidKeyController(
        keyMapping: keyMapping,
        wallet: wallet,
      );
    });

    test('should create DidKeyPair through DidController.getKey()', () async {
      // Create a key in the wallet first
      final walletKeyId = 'test-key-auth';
      await wallet.generateKey(keyId: walletKeyId, keyType: KeyType.ed25519);

      // Add it as an authentication method
      final verificationMethodId =
          await didKeyController.addAuthenticationVerificationMethod(
        KeyType.ed25519,
        walletKeyId,
      );

      // Get the DidKeyPair
      final didKeyPair = await didKeyController.getKey(verificationMethodId);

      // Verify the DidKeyPair properties
      expect(didKeyPair.verificationMethodId, equals(verificationMethodId));
      expect(didKeyPair.walletKeyId, isNotEmpty);
      expect(didKeyPair.publicKey, isNotNull);
      expect(didKeyPair.publicKey.type, equals(KeyType.ed25519));
      expect(didKeyPair.did, startsWith('did:key:'));
      expect(didKeyPair.didDocument, isNotNull);
      expect(didKeyPair.supportedSignatureSchemes, isNotEmpty);

      // Verify the verification method ID format
      expect(verificationMethodId, contains('#z'));
      expect(verificationMethodId, startsWith('did:key:z'));
    });

    test('should sign and verify using DidKeyPair', () async {
      // Create a key in the wallet first
      final walletKeyId = 'test-key-assertion';
      await wallet.generateKey(keyId: walletKeyId, keyType: KeyType.p256);

      // Add it as an assertion method
      final verificationMethodId =
          await didKeyController.addAssertionMethodVerificationMethod(
        KeyType.p256,
        walletKeyId,
      );

      // Get the DidKeyPair
      final didKeyPair = await didKeyController.getKey(verificationMethodId);

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
        () => didKeyController.getKey('non-existent-key-id'),
        throwsA(isA<SsiException>().having(
          (e) => e.code,
          'code',
          SsiExceptionType.keyNotFound.code,
        )),
      );
    });

    test('should maintain proper key mapping between DID and wallet IDs',
        () async {
      // Create a key in the wallet first
      final walletKeyId = 'test-key-agreement';
      await wallet.generateKey(keyId: walletKeyId, keyType: KeyType.ed25519);

      // Add it as a key agreement method
      final verificationMethodId =
          await didKeyController.addKeyAgreementVerificationMethod(
        KeyType.ed25519,
        walletKeyId,
      );

      // Get the DidKeyPair
      final didKeyPair = await didKeyController.getKey(verificationMethodId);

      // Verify the mapping
      final mappedWalletKeyId = keyMapping.getWalletKeyId(verificationMethodId);
      expect(mappedWalletKeyId, equals(didKeyPair.walletKeyId));
      expect(mappedWalletKeyId, equals(didKeyPair.keyPair.id));
    });

    test(
        'should work with existing key added via addAuthenticationVerificationMethod',
        () async {
      // Create a key in the wallet first
      final walletKeyId = 'test-key-123';
      await wallet.generateKey(keyId: walletKeyId, keyType: KeyType.ed25519);

      // Add it to the DID document as authentication method
      final verificationMethodId =
          await didKeyController.addAuthenticationVerificationMethod(
        KeyType.ed25519,
        walletKeyId,
      );

      // Get the DidKeyPair
      final didKeyPair = await didKeyController.getKey(verificationMethodId);

      // Verify it references the same wallet key
      expect(didKeyPair.walletKeyId, equals(walletKeyId));
      expect(didKeyPair.keyPair.id, equals(walletKeyId));
      expect(didKeyPair.publicKey.type, equals(KeyType.ed25519));
    });

    test('should create keys with different verification method purposes',
        () async {
      // Create keys in wallet first
      final authKeyId = 'test-key-auth-multi';
      final assertionKeyId = 'test-key-assertion-multi';
      final keyAgreementKeyId = 'test-key-agreement-multi';

      await wallet.generateKey(keyId: authKeyId, keyType: KeyType.ed25519);
      await wallet.generateKey(keyId: assertionKeyId, keyType: KeyType.p256);
      await wallet.generateKey(
          keyId: keyAgreementKeyId, keyType: KeyType.ed25519);

      // Add keys with different purposes
      await didKeyController.addAuthenticationVerificationMethod(
        KeyType.ed25519,
        authKeyId,
      );

      await didKeyController.addAssertionMethodVerificationMethod(
        KeyType.p256,
        assertionKeyId,
      );

      await didKeyController.addKeyAgreementVerificationMethod(
        KeyType.ed25519,
        keyAgreementKeyId,
      );

      // Get the DID document
      final didDocument = await didKeyController.getDidDocument();

      // Verify that the methods are in the appropriate arrays
      // For did:key, the verification methods are already included in the generated document
      // Check that the document contains the appropriate verification methods
      expect(didDocument.authentication, isNotEmpty);
      expect(didDocument.assertionMethod, isNotEmpty);
      expect(didDocument.keyAgreement, isNotEmpty);

      // The verification methods should be references to the methods in the verificationMethod array
      expect(didDocument.verificationMethod, hasLength(greaterThan(0)));

      // Verify the document has the correct DID
      expect(didDocument.id, startsWith('did:key:'));
    });
  });
}
