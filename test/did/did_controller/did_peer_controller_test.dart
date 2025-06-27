import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidPeerController', () {
    late Wallet wallet;
    late DiDControllerStore keyMapping;
    late DidPeerController controller;

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      keyMapping = DefaultDiDControllerStore();
      controller = DidPeerController(
        keyMapping: keyMapping,
        wallet: wallet,
      );
    });

    group('Multiple keys with different purposes', () {
      test('should create document with authentication and key agreement keys',
          () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'auth-key');
        final kaKey = await wallet.generateKey(keyId: 'ka-key');

        // Act
        final document = await controller.createDidDocumentWithKeys(
          [authKey.id],
          [kaKey.id],
        );

        // Assert
        expect(document.id, startsWith('did:peer:2'));
        expect(document.verificationMethod.length, 2);
        expect(document.authentication.length, 1);
        expect(document.keyAgreement.length, 1);
        expect(document.assertionMethod.length,
            1); // Auth keys are added to all purposes
        expect(document.capabilityInvocation.length, 1);
        expect(document.capabilityDelegation.length, 1);
      });

      test('should create document with multiple authentication keys',
          () async {
        // Arrange
        final authKey1 = await wallet.generateKey(keyId: 'auth-key-1');
        final authKey2 = await wallet.generateKey(keyId: 'auth-key-2');
        final authKey3 = await wallet.generateKey(keyId: 'auth-key-3');

        // Act
        final document = await controller.createDidDocumentWithKeys(
          [authKey1.id, authKey2.id, authKey3.id],
          [],
        );

        // Assert
        expect(document.verificationMethod.length, 3);
        expect(document.authentication.length, 3);
        expect(document.keyAgreement.length, 0);
        expect(document.assertionMethod.length,
            3); // Auth keys are added to all purposes
        expect(document.capabilityInvocation.length, 3);
        expect(document.capabilityDelegation.length, 3);
      });

      test('should create document with multiple key agreement keys', () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'auth-key');
        final kaKey1 = await wallet.generateKey(keyId: 'ka-key-1');
        final kaKey2 = await wallet.generateKey(keyId: 'ka-key-2');

        // Act
        final document = await controller.createDidDocumentWithKeys(
          [authKey.id],
          [kaKey1.id, kaKey2.id],
        );

        // Assert
        expect(document.verificationMethod.length, 3);
        expect(document.authentication.length, 1);
        expect(document.keyAgreement.length, 2);
      });

      test('should handle keys with mixed purposes', () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'auth-key');
        final kaKey = await wallet.generateKey(keyId: 'ka-key');

        controller.addAuthenticationKey(authKey.id);
        controller.addKeyAgreementKey(kaKey.id);
        controller.addCapabilityInvocationKey(authKey.id);
        controller.addAssertionMethodKey(authKey.id);

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.verificationMethod.length, 2);
        // Authentication key is added second, so it gets #key-2
        expect(document.authentication.any((ref) => ref.id.contains('#key-2')),
            isTrue);
        // Key agreement key is added first, so it gets #key-1
        expect(document.keyAgreement.any((ref) => ref.id.contains('#key-1')),
            isTrue);
        expect(
            document.capabilityInvocation
                .any((ref) => ref.id.contains('#key-2')),
            isTrue);
        expect(document.assertionMethod.any((ref) => ref.id.contains('#key-2')),
            isTrue);
      });
    });

    group('Service endpoint handling', () {
      test('should create document with service endpoint', () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'auth-key');
        final serviceEndpoint = const MapEndpoint({
          'uri': 'https://example.com/endpoint',
          'accept': ['application/json'],
          'routingKeys': <String>[],
        });

        // Act
        final document = await controller.createDidDocumentWithKeys(
          [authKey.id],
          [],
          serviceEndpoint: serviceEndpoint,
        );

        // Assert
        expect(document.service.length, 1);
        expect(document.service[0].type, 'GenericService');
        expect(document.service[0].serviceEndpoint, isA<MapEndpoint>());

        final endpoint = document.service[0].serviceEndpoint as MapEndpoint;
        expect(endpoint.data['uri'], 'https://example.com/endpoint');
      });

      test('should update service endpoint', () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'auth-key');
        final endpoint1 = const StringEndpoint('https://example1.com');
        final endpoint2 = const StringEndpoint('https://example2.com');

        // Act
        controller.setServiceEndpoint(endpoint1);
        controller.addAuthenticationKey(authKey.id);
        final doc1 = await controller.getDidDocument();

        controller.setServiceEndpoint(endpoint2);
        final doc2 = await controller.getDidDocument();

        // Assert
        expect(doc1.service.length, 1);
        expect((doc1.service[0].serviceEndpoint as StringEndpoint).url,
            'https://example1.com');

        expect(doc2.service.length, 1);
        expect((doc2.service[0].serviceEndpoint as StringEndpoint).url,
            'https://example2.com');
      });

      test('should create document without service endpoint', () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'auth-key');

        // Act
        final document = await controller.createDidDocumentWithKeys(
          [authKey.id],
          [],
        );

        // Assert
        expect(document.service.length, 0);
      });
    });

    group('Proper indexing in verification method IDs', () {
      test('should use sequential numbering for verification method IDs',
          () async {
        // Arrange
        final authKey1 = await wallet.generateKey(keyId: 'auth-1');
        final authKey2 = await wallet.generateKey(keyId: 'auth-2');
        final kaKey = await wallet.generateKey(keyId: 'ka-1');

        // Act
        controller.addAuthenticationKey(authKey1.id);
        controller.addAuthenticationKey(authKey2.id);
        controller.addKeyAgreementKey(kaKey.id);

        final vmId1 = await controller.findVerificationMethodId(authKey1.id);
        final vmId2 = await controller.findVerificationMethodId(authKey2.id);
        final vmId3 = await controller.findVerificationMethodId(kaKey.id);

        // Assert
        expect(vmId1, '#key-1');
        expect(vmId2, '#key-2');
        expect(vmId3, '#key-3');
      });

      test('should maintain consistent indexing across purposes', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'key-1');
        final key2 = await wallet.generateKey(keyId: 'key-2');
        final key3 = await wallet.generateKey(keyId: 'key-3');

        // Act
        controller.addAuthenticationKey(key1.id);
        controller.addKeyAgreementKey(key2.id);
        controller.addCapabilityInvocationKey(key3.id);

        final document = await controller.getDidDocument();

        // Assert
        expect(document.verificationMethod.length, 3);
        expect(document.verificationMethod[0].id, contains('#key-1'));
        expect(document.verificationMethod[1].id, contains('#key-2'));
        expect(document.verificationMethod[2].id, contains('#key-3'));
      });

      test('should handle duplicate keys across purposes correctly', () async {
        // Arrange
        final sharedKey = await wallet.generateKey(keyId: 'shared-key');

        // Act
        controller.addAuthenticationKey(sharedKey.id);
        controller.addCapabilityInvocationKey(sharedKey.id);
        controller.addAssertionMethodKey(sharedKey.id);

        final vmId = await controller.findVerificationMethodId(sharedKey.id);
        final document = await controller.getDidDocument();

        // Assert
        expect(vmId, '#key-1');
        expect(document.verificationMethod.length, 1);
        expect(document.authentication.length, 1);
        expect(document.capabilityInvocation.length, 1);
        expect(document.assertionMethod.length, 1);
      });
    });

    group('Complex scenarios', () {
      test('should handle mixed key types', () async {
        // Arrange
        final p256Key = await wallet.generateKey(
          keyId: 'p256-key',
          keyType: KeyType.p256,
        );
        final ed25519Key = await wallet.generateKey(
          keyId: 'ed25519-key',
          keyType: KeyType.ed25519,
        );
        final p256Key2 = await wallet.generateKey(
          keyId: 'p256-key-2',
          keyType: KeyType.p256,
        );

        // Act
        final document = await controller.createDidDocumentWithKeys(
          [p256Key.id, ed25519Key.id],
          [p256Key2.id],
        );

        // Assert
        expect(document.verificationMethod.length, 3);
        expect(document.authentication.length, 2);
        expect(document.keyAgreement.length, 1);

        // Verify different key types are properly represented
        final vm1 = document.verificationMethod[0];
        final vm2 = document.verificationMethod[1];
        final vm3 = document.verificationMethod[2];

        // did:peer uses specific key types not Multikey
        expect(vm1.type,
            anyOf('Ed25519VerificationKey2020', 'X25519KeyAgreementKey2020'));
        expect(vm2.type,
            anyOf('Ed25519VerificationKey2020', 'X25519KeyAgreementKey2020'));
        expect(vm3.type,
            anyOf('Ed25519VerificationKey2020', 'X25519KeyAgreementKey2020'));
      });

      test('should handle complex verification method purposes', () async {
        // Arrange
        final authOnlyKey = await wallet.generateKey(keyId: 'auth-only');
        final kaOnlyKey = await wallet.generateKey(keyId: 'ka-only');
        final multiPurposeKey =
            await wallet.generateKey(keyId: 'multi-purpose');

        // Act
        controller.addAuthenticationKey(authOnlyKey.id);
        controller.addKeyAgreementKey(kaOnlyKey.id);
        controller.addAuthenticationKey(multiPurposeKey.id);
        controller.addCapabilityInvocationKey(multiPurposeKey.id);
        controller.addCapabilityDelegationKey(multiPurposeKey.id);
        controller.addAssertionMethodKey(multiPurposeKey.id);

        final document = await controller.getDidDocument();

        // Assert
        expect(document.verificationMethod.length, 3);
        expect(
            document.authentication.length, 2); // authOnlyKey + multiPurposeKey
        expect(document.keyAgreement.length, 1); // kaOnlyKey
        expect(document.capabilityInvocation.length,
            2); // authOnlyKey + multiPurposeKey (auth keys get all purposes)
        expect(document.capabilityDelegation.length,
            2); // authOnlyKey + multiPurposeKey (auth keys get all purposes)
        expect(document.assertionMethod.length,
            2); // authOnlyKey + multiPurposeKey (auth keys get all purposes)
      });

      test('should sign and verify with multiple keys', () async {
        // Arrange
        final authKey1 = await wallet.generateKey(keyId: 'sign-key-1');
        final authKey2 = await wallet.generateKey(keyId: 'sign-key-2');

        // Use addAuthenticationVerificationMethod which sets up mappings
        final vmId1 = await controller.addAuthenticationVerificationMethod(
            authKey1.publicKey.type, authKey1.id);
        final vmId2 = await controller.addAuthenticationVerificationMethod(
            authKey2.publicKey.type, authKey2.id);

        final data = Uint8List.fromList('Test data'.codeUnits);

        // Act
        final signature1 = await controller.sign(data, vmId1);
        final signature2 = await controller.sign(data, vmId2);

        final isValid1 = await controller.verify(data, signature1, vmId1);
        final isValid2 = await controller.verify(data, signature2, vmId2);

        // Assert
        expect(isValid1, isTrue);
        expect(isValid2, isTrue);
        expect(signature1, isNot(equals(signature2)));
      });
    });

    group('Document creation and updates', () {
      test('should throw error when creating document without keys', () async {
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

      test('should update document when keys change', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'update-key-1');
        final key2 = await wallet.generateKey(keyId: 'update-key-2');
        final key3 = await wallet.generateKey(keyId: 'update-key-3');

        // Act
        await controller.createDidDocumentWithKeys([key1.id], []);
        final doc1 = await controller.getDidDocument();

        await controller
            .createDidDocumentWithKeys([key1.id, key2.id], [key3.id]);
        final doc2 = await controller.getDidDocument();

        // Assert
        expect(doc1.verificationMethod.length, 1);
        expect(doc2.verificationMethod.length, 3);
        expect(
            doc1.id, isNot(equals(doc2.id))); // DID changes with different keys
      });

      test('should clear previous keys when using createDidDocumentWithKeys',
          () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'clear-key-1');
        final key2 = await wallet.generateKey(keyId: 'clear-key-2');
        final key3 = await wallet.generateKey(keyId: 'clear-key-3');

        // Act
        controller.addAuthenticationKey(key1.id);
        controller.addKeyAgreementKey(key2.id);

        // This should clear previous keys
        await controller.createDidDocumentWithKeys([key3.id], []);
        final document = await controller.getDidDocument();

        // Assert
        expect(document.verificationMethod.length, 1);
        expect(document.authentication.length, 1);
        expect(document.keyAgreement.length, 0);
      });
    });

    group('findVerificationMethodId', () {
      test('should find correct ID for each key', () async {
        // Arrange
        final keys = await Future.wait([
          wallet.generateKey(keyId: 'find-key-1'),
          wallet.generateKey(keyId: 'find-key-2'),
          wallet.generateKey(keyId: 'find-key-3'),
        ]);

        controller.addAuthenticationKey(keys[0].id);
        controller.addKeyAgreementKey(keys[1].id);
        controller.addAssertionMethodKey(keys[2].id);

        // Act
        final vmIds = await Future.wait([
          controller.findVerificationMethodId(keys[0].id),
          controller.findVerificationMethodId(keys[1].id),
          controller.findVerificationMethodId(keys[2].id),
        ]);

        // Assert
        expect(vmIds[0], '#key-1'); // authentication comes first
        expect(vmIds[1], '#key-3'); // keyAgreement comes after assertionMethod
        expect(vmIds[2], '#key-2'); // assertionMethod comes before keyAgreement
      });

      test('should throw error for unknown key', () async {
        // Arrange
        final key = await wallet.generateKey(keyId: 'known-key');
        controller.addAuthenticationKey(key.id);

        // Act & Assert
        expect(
          () => controller.findVerificationMethodId('unknown-key'),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.keyNotFound.code,
            ),
          ),
        );
      });
    });

    group('Integration with base controller methods', () {
      test('should work with addAuthenticationVerificationMethod', () async {
        // Arrange
        final key = await wallet.generateKey(keyId: 'add-auth-key');

        // Act
        // First create a basic document to establish the DID
        await controller.createDidDocumentWithKeys([key.id], []);

        // Now we can use the verification method that was created
        final vmId = await controller.findVerificationMethodId(key.id);
        keyMapping.setMapping(vmId, key.id);

        final document = await controller.getDidDocument();

        // Assert
        expect(vmId, '#key-1');
        expect(document.authentication.length, 1);
        expect(keyMapping.getWalletKeyId(vmId), key.id);
      });

      test('should work with all add verification method types', () async {
        // Arrange
        final keys = await Future.wait([
          wallet.generateKey(keyId: 'auth-vm'),
          wallet.generateKey(keyId: 'ka-vm'),
          wallet.generateKey(keyId: 'ci-vm'),
          wallet.generateKey(keyId: 'cd-vm'),
          wallet.generateKey(keyId: 'am-vm'),
        ]);

        // Act
        final vmIds = await Future.wait([
          controller.addAuthenticationVerificationMethod(
              keys[0].publicKey.type, keys[0].id),
          controller.addKeyAgreementVerificationMethod(
              keys[1].publicKey.type, keys[1].id),
          controller.addCapabilityInvocationVerificationMethod(
              keys[2].publicKey.type, keys[2].id),
          controller.addCapabilityDelegationVerificationMethod(
              keys[3].publicKey.type, keys[3].id),
          controller.addAssertionMethodVerificationMethod(
              keys[4].publicKey.type, keys[4].id),
        ]);

        final document = await controller.getDidDocument();

        // Assert
        expect(vmIds[0], '#key-1'); // authentication
        expect(vmIds[1], '#key-2'); // keyAgreement
        expect(vmIds[2],
            '#key-2'); // capabilityInvocation (gets same ID as it comes before keyAgreement in ordering)
        expect(vmIds[3], '#key-3'); // capabilityDelegation
        expect(vmIds[4], '#key-4'); // assertionMethod
        expect(document.verificationMethod.length, 5);
      });

      test('should get DID signer for verification method', () async {
        // Arrange
        final key = await wallet.generateKey(keyId: 'signer-key');
        await controller.createDidDocumentWithKeys([key.id], []);
        final vmId = await controller.findVerificationMethodId(key.id);
        keyMapping.setMapping(vmId, key.id);

        // Act
        final signer = await controller.getSigner(vmId);

        // Assert
        expect(signer.didKeyId, vmId);
        expect(signer.signatureScheme, isNotNull);
      });
    });
  });
}
