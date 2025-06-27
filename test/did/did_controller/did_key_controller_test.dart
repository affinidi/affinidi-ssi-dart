import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidKeyController', () {
    late Wallet wallet;
    late DiDControllerStore keyMapping;
    late DidKeyController controller;

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      keyMapping = DefaultDiDControllerStore();
      controller = DidKeyController(
        keyMapping: keyMapping,
        wallet: wallet,
      );
    });

    group('Construction from different key types', () {
      test('should create controller with P256 key', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'p256-key',
          keyType: KeyType.p256,
        );

        // Act
        final document = await controller.createDidDocumentFromKey(keyPair.id);

        // Assert
        expect(document.id, startsWith('did:key:zDn'));
        expect(document.verificationMethod.length, 1);
        expect(document.verificationMethod[0].type, 'P256Key2021');
        expect(document.authentication.length, 1);
        expect(document.assertionMethod.length, 1);
        expect(document.keyAgreement.length, 1); // P256 includes keyAgreement
        expect(document.capabilityInvocation.length,
            1); // P256 includes all purposes
        expect(document.capabilityDelegation.length,
            1); // P256 includes all purposes
      });

      test('should create controller with ED25519 key', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'ed25519-key',
          keyType: KeyType.ed25519,
        );

        // Act
        final document = await controller.createDidDocumentFromKey(keyPair.id);

        // Assert
        expect(document.id, startsWith('did:key:z6Mk'));
        expect(document.verificationMethod.length,
            2); // ED25519 includes X25519 key agreement
        expect(
            document.verificationMethod[0].type, 'Ed25519VerificationKey2020');
        expect(document.authentication.length, 1);
        expect(document.assertionMethod.length, 1);
        expect(document.keyAgreement.length, 1);
      });

      test('should create controller with secp256k1 key', () async {
        // Skip test as PersistentWallet doesn't support secp256k1
      }, skip: 'PersistentWallet does not support secp256k1');
    });

    group('createDocument()', () {
      test('should create document from single key', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'test-key');

        // Act
        final document = await controller.createDidDocumentFromKey(keyPair.id);

        // Assert
        expect(document.verificationMethod.length, 1);
        expect(document.verificationMethod[0].controller, document.id);
        expect(document.verificationMethod[0].id, contains('#'));
      });

      test('should verify single verification method constraint', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'key-1');
        final key2 = await wallet.generateKey(keyId: 'key-2');

        // Act - Create document with first key
        final doc1 = await controller.createDidDocumentFromKey(key1.id);

        // Create document with second key (should replace first)
        final doc2 = await controller.createDidDocumentFromKey(key2.id);

        // Assert - Only one verification method
        expect(doc1.verificationMethod.length, 1);
        expect(doc2.verificationMethod.length, 1);

        // DIDs should be different
        expect(doc1.id, isNot(equals(doc2.id)));
      });

      test('should use key for specified purpose', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'ka-key');

        // Act
        final document = await controller.createDidDocumentFromKey(
          keyPair.id,
          VerificationMethodPurpose.keyAgreement,
        );

        // Assert - For did:key, all verification relationships are always present
        expect(document.authentication.length, 1);
        expect(document.assertionMethod.length, 1);
        // Key agreement is always included for did:key
        expect(document.keyAgreement.length,
            keyPair.publicKey.type == KeyType.ed25519 ? 1 : 1);
      });

      test('should throw error when creating document without key', () async {
        // Act & Assert
        expect(
          () => controller.createOrUpdateDocument(),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.invalidDidDocument.code,
            ),
          ),
        );
      });
    });

    group('ID generation pattern', () {
      test('should generate proper ID pattern for P256', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'p256-test',
          keyType: KeyType.p256,
        );

        // Act
        final document = await controller.createDidDocumentFromKey(keyPair.id);
        final vmId = document.verificationMethod[0].id;

        // Assert
        expect(document.id, matches(RegExp(r'^did:key:zDn[a-zA-Z0-9]+$')));
        expect(vmId, startsWith(document.id));
        expect(vmId, contains('#'));
      });

      test('should generate proper ID pattern for ED25519', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'ed25519-test',
          keyType: KeyType.ed25519,
        );

        // Act
        final document = await controller.createDidDocumentFromKey(keyPair.id);
        final vmId = document.verificationMethod[0].id;

        // Assert
        expect(document.id, matches(RegExp(r'^did:key:z6Mk[a-zA-Z0-9]+$')));
        expect(vmId, startsWith(document.id));
        expect(vmId, contains('#'));
      });

      test('should generate proper ID pattern for secp256k1', () async {
        // Skip test as PersistentWallet doesn't support secp256k1
      }, skip: 'PersistentWallet does not support secp256k1');
    });

    group('Integration with wallet', () {
      test('should sign and verify with did:key controller', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'sign-key');
        final document = await controller.createDidDocumentFromKey(keyPair.id);
        final vmId = document.verificationMethod[0].id;
        keyMapping.setMapping(vmId, keyPair.id);

        final data = Uint8List.fromList('Hello, World!'.codeUnits);

        // Act
        final signature = await controller.sign(data, vmId);
        final isValid = await controller.verify(data, signature, vmId);

        // Assert
        expect(isValid, isTrue);
      });

      test('should retrieve correct key pair', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'retrieve-key');
        final document = await controller.createDidDocumentFromKey(keyPair.id);
        final vmId = document.verificationMethod[0].id;
        keyMapping.setMapping(vmId, keyPair.id);

        // Act
        final retrievedKey = await controller.getKey(vmId);

        // Assert
        expect(retrievedKey.keyPair.id, keyPair.id);
        expect(retrievedKey.verificationMethodId, vmId);
        expect(retrievedKey.didDocument?.id, document.id);
      });

      test('should get DID signer', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'signer-key');
        final document = await controller.createDidDocumentFromKey(keyPair.id);
        final vmId = document.verificationMethod[0].id;
        keyMapping.setMapping(vmId, keyPair.id);

        // Act
        final signer = await controller.getSigner(vmId);

        // Assert
        expect(signer.didKeyId, vmId);
        expect(signer.signatureScheme, isNotNull);
      });
    });

    group('findVerificationMethodId', () {
      test('should find verification method ID for primary key', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'primary-key');
        await controller.createDidDocumentFromKey(keyPair.id);

        // Act
        final vmId = await controller.findVerificationMethodId(keyPair.id);

        // Assert
        expect(vmId, contains('did:key:'));
        expect(vmId, contains('#'));
      });

      test('should throw error when no primary key is set', () async {
        // Act & Assert
        expect(
          () => controller.findVerificationMethodId('some-key'),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.invalidDidDocument.code,
            ),
          ),
        );
      });
    });

    group('getDidDocument', () {
      test('should return current DID document', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'doc-key');
        await controller.createDidDocumentFromKey(keyPair.id);

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.id, startsWith('did:key:'));
        expect(document.verificationMethod.length, 1);
      });

      test('should reflect latest state after key changes', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'key-1');
        final key2 = await wallet.generateKey(keyId: 'key-2');

        // Act
        await controller.createDidDocumentFromKey(key1.id);
        final doc1 = await controller.getDidDocument();

        await controller.createDidDocumentFromKey(key2.id);
        final doc2 = await controller.getDidDocument();

        // Assert
        expect(doc1.id, isNot(equals(doc2.id)));
        expect(doc1.verificationMethod[0].id,
            isNot(equals(doc2.verificationMethod[0].id)));
      });
    });

    group('edge cases', () {
      test('should handle key replacement', () async {
        // Arrange
        final key1 = await wallet.generateKey(
          keyId: 'replace-key-1',
          keyType: KeyType.p256,
        );
        final key2 = await wallet.generateKey(
          keyId: 'replace-key-2',
          keyType: KeyType.ed25519,
        );

        // Act
        final doc1 = await controller.createDidDocumentFromKey(key1.id);
        final doc2 = await controller.createDidDocumentFromKey(key2.id);

        // Assert
        expect(doc1.id, startsWith('did:key:zDn')); // P256
        expect(doc2.id, startsWith('did:key:z6Mk')); // ED25519
        expect(doc1.id, isNot(equals(doc2.id)));
      });

      test(
          'should maintain single key constraint with addAuthenticationVerificationMethod',
          () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'auth-key-1');
        final key2 = await wallet.generateKey(keyId: 'auth-key-2');

        // Act
        await controller.createDidDocumentFromKey(key1.id);

        // This should still work but only the last key is used for did:key
        await controller.addAuthenticationVerificationMethod(
          key2.publicKey.type,
          key2.id,
        );

        final document = await controller.getDidDocument();

        // Assert - did:key always has single verification method
        expect(document.verificationMethod.length, 1);
      });
    });
  });
}
