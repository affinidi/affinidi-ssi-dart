import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidKeyPair Tests', () {
    late Wallet wallet;
    late DidKeyManager didKeyManager;
    late InMemoryDidKeyMappingStore keyMappingStore;
    late InMemoryDidDocumentReferenceStore documentReferenceStore;
    setUp(() async {
      wallet = PersistentWallet(InMemoryKeyStore());
      keyMappingStore = InMemoryDidKeyMappingStore();
      documentReferenceStore = InMemoryDidDocumentReferenceStore();
      didKeyManager = DidKeyManager(
        wallet: wallet,
        keyMappingStore: keyMappingStore,
        documentReferenceStore: documentReferenceStore,
      );
    });

    test('should create DidKeyPair through DidManager.getKey()', () async {
      // Create a key in the wallet first
      final key = await wallet.generateKey(keyType: KeyType.ed25519);

      // Add it as a verification method
      final result = await didKeyManager.addVerificationMethod(key.id);
      final verificationMethodId = result.verificationMethodId;

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

      // Verify the verification method ID format
      expect(verificationMethodId, contains('#z'));
      expect(verificationMethodId, startsWith('did:key:z'));
    });

    test('should sign and verify using DidKeyPair', () async {
      // Create a key in the wallet first
      final key = await wallet.generateKey(keyType: KeyType.p256);

      // Add it as a verification method
      final result = await didKeyManager.addVerificationMethod(key.id);
      final verificationMethodId = result.verificationMethodId;

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
      // Create a key in the wallet first
      final key = await wallet.generateKey(keyType: KeyType.ed25519);

      // Add it as a verification method
      final result = await didKeyManager.addVerificationMethod(key.id);
      final verificationMethodId = result.verificationMethodId;

      // Get the DidKeyPair
      final didKeyPair = await didKeyManager.getKey(verificationMethodId);

      // Verify the mapping
      final mappedWalletKeyId =
          await didKeyManager.getWalletKeyId(verificationMethodId);
      expect(mappedWalletKeyId, equals(didKeyPair.walletKeyId));
      expect(mappedWalletKeyId, equals(didKeyPair.keyPair.id));
    });
  });
}
