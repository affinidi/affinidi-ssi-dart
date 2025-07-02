import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidPeerController', () {
    late Wallet wallet;
    late DidStore store;
    late DidPeerController controller;

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      store = InMemoryDidStore();
      controller = DidPeerController(
        store: store,
        wallet: wallet,
      );
    });

    group('addVerificationMethod', () {
      test('should add multiple verification methods', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'key-1');
        final key2 = await wallet.generateKey(keyId: 'key-2');
        final key3 = await wallet.generateKey(keyId: 'key-3');

        // Act
        final res1 =
            await controller.addVerificationMethod(key1.id, relationships: {});
        final res2 =
            await controller.addVerificationMethod(key2.id, relationships: {});
        final res3 =
            await controller.addVerificationMethod(key3.id, relationships: {});

        // Assert
        expect(res1.verificationMethodId, '#key-1');
        expect(res2.verificationMethodId, '#key-2');
        expect(res3.verificationMethodId, '#key-3');
      });

      test('should maintain 1-based indexing', () async {
        // Arrange
        final keys = await Future.wait([
          wallet.generateKey(keyId: 'idx-key-1'),
          wallet.generateKey(keyId: 'idx-key-2'),
          wallet.generateKey(keyId: 'idx-key-3'),
        ]);

        // Act
        final vmIds = <String>[];
        for (final key in keys) {
          final res =
              await controller.addVerificationMethod(key.id, relationships: {});
          vmIds.add(res.verificationMethodId);
        }

        // Assert
        expect(vmIds, ['#key-1', '#key-2', '#key-3']);
      });
    });

    group('getDidDocument', () {
      test('should create document with authentication and key agreement keys',
          () async {
        // Arrange
        final key = await wallet.generateKey(
            keyId: 'auth-and-ka-key', keyType: KeyType.ed25519);

        // Add verification methods
        final result = await controller.addVerificationMethod(key.id,
            relationships: {
              VerificationRelationship.authentication,
              VerificationRelationship.keyAgreement
            });

        // Set purposes
        final authVmId =
            result.relationships[VerificationRelationship.authentication]!;
        final kaVmId =
            result.relationships[VerificationRelationship.keyAgreement]!;

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.id, startsWith('did:peer:2'));
        expect(document.verificationMethod.length, 2);
        expect(document.authentication.length, 1);
        expect(document.keyAgreement.length, 1);
        expect(document.authentication[0].id, authVmId);
        expect(document.keyAgreement[0].id, kaVmId);
      });

      test('should throw error when no keys are added', () async {
        // Act & Assert
        expect(
          () => controller.getDidDocument(),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.invalidDidDocument.code,
            ),
          ),
        );
      });

      test('should create document with multiple authentication keys',
          () async {
        // Arrange
        final auth1 = await wallet.generateKey(keyId: 'auth-1');
        final auth2 = await wallet.generateKey(keyId: 'auth-2');
        final auth3 = await wallet.generateKey(keyId: 'auth-3');

        // Add verification methods and set purposes
        final res1 = await controller.addVerificationMethod(auth1.id,
            relationships: {VerificationRelationship.authentication});
        final res2 = await controller.addVerificationMethod(auth2.id,
            relationships: {VerificationRelationship.authentication});
        final res3 = await controller.addVerificationMethod(auth3.id,
            relationships: {VerificationRelationship.authentication});
        final vmId1 = res1.verificationMethodId;
        final vmId2 = res2.verificationMethodId;
        final vmId3 = res3.verificationMethodId;

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.verificationMethod.length, 3);
        expect(document.authentication.length, 3);
        expect(document.authentication.map((ref) => ref.id).toList(),
            containsAll([vmId1, vmId2, vmId3]));
      });

      test('should handle authentication and key agreement purposes', () async {
        // Arrange
        final key1 =
            await wallet.generateKey(keyId: 'auth-1', keyType: KeyType.ed25519);
        final key2 =
            await wallet.generateKey(keyId: 'auth-2', keyType: KeyType.ed25519);
        final key3 =
            await wallet.generateKey(keyId: 'ka-1', keyType: KeyType.ed25519);

        // Add verification methods
        final res1 = await controller.addVerificationMethod(key1.id,
            relationships: {VerificationRelationship.authentication});
        final res2 = await controller.addVerificationMethod(key2.id,
            relationships: {VerificationRelationship.authentication});
        final res3 = await controller.addVerificationMethod(key3.id,
            relationships: {VerificationRelationship.keyAgreement});
        final vmId1 = res1.verificationMethodId;
        final vmId2 = res2.verificationMethodId;
        final vmId3 =
            res3.relationships[VerificationRelationship.keyAgreement]!;

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.verificationMethod.length, 3);
        expect(document.authentication.length, 2);
        expect(document.keyAgreement.length, 1);
        expect(document.authentication.any((ref) => ref.id == vmId1), isTrue);
        expect(document.authentication.any((ref) => ref.id == vmId2), isTrue);
        expect(document.keyAgreement.any((ref) => ref.id == vmId3), isTrue);

        // did:peer:2 doesn't populate other verification method purposes
        expect(document.assertionMethod, isEmpty);
        expect(document.capabilityInvocation, isEmpty);
        expect(document.capabilityDelegation, isEmpty);
      });
    });

    group('Service endpoints', () {
      test('should add single service endpoint', () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'service-auth-key');
        await controller.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        final endpoint = ServiceEndpoint(
          id: '#service-1',
          type: 'MessagingService',
          serviceEndpoint:
              const StringEndpoint('https://example.com/messaging'),
        );

        // Act
        await controller.addServiceEndpoint(endpoint);
        final document = await controller.getDidDocument();

        // Assert
        expect(document.service.length, 1);
        expect(document.service[0].id, '#service-1');
        expect(document.service[0].type, 'MessagingService');
        expect((document.service[0].serviceEndpoint as StringEndpoint).url,
            'https://example.com/messaging');
      });

      test('should add multiple service endpoints', () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'multi-service-key');
        await controller.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        final endpoint1 = ServiceEndpoint(
          id: '#service-1',
          type: 'MessagingService',
          serviceEndpoint:
              const StringEndpoint('https://example.com/messaging'),
        );

        final endpoint2 = ServiceEndpoint(
          id: '#service-2',
          type: 'CredentialService',
          serviceEndpoint: const MapEndpoint({
            'uri': 'https://example.com/credentials',
            'accept': ['application/json'],
          }),
        );

        // Act
        await controller.addServiceEndpoint(endpoint1);
        await controller.addServiceEndpoint(endpoint2);
        final document = await controller.getDidDocument();

        // Assert
        expect(document.service.length, 2);
        expect(document.service.map((s) => s.id).toList(),
            containsAll(['#service-1', '#service-2']));
      });

      test('should remove service endpoint', () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'remove-service-key');
        await controller.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        final endpoint = ServiceEndpoint(
          id: '#service-to-remove',
          type: 'TestService',
          serviceEndpoint: const StringEndpoint('https://example.com'),
        );

        // Act
        await controller.addServiceEndpoint(endpoint);
        final docBefore = await controller.getDidDocument();

        await controller.removeServiceEndpoint('#service-to-remove');
        final docAfter = await controller.getDidDocument();

        // Assert
        expect(docBefore.service.length, 1);
        expect(docAfter.service.length, 0);
      });

      test('should throw error when adding duplicate service endpoint',
          () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'dup-service-key');
        await controller.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        final endpoint = ServiceEndpoint(
          id: '#duplicate-service',
          type: 'TestService',
          serviceEndpoint: const StringEndpoint('https://example.com'),
        );

        // Act
        await controller.addServiceEndpoint(endpoint);

        // Assert
        expect(
          () => controller.addServiceEndpoint(endpoint),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.other.code,
            ),
          ),
        );
      });
    });

    group('Signing and verification', () {
      test('should sign and verify with authentication key', () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'sign-auth-key');
        final result = await controller.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});
        final vmId = result.verificationMethodId;

        final data = Uint8List.fromList('Hello, DID Peer!'.codeUnits);

        // Act
        final signature = await controller.sign(data, vmId);
        final isValid = await controller.verify(data, signature, vmId);

        // Assert
        expect(isValid, isTrue);
      });

      test('should sign and verify with different keys', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'sign-key-1');
        final key2 = await wallet.generateKey(keyId: 'sign-key-2');

        final res1 = await controller.addVerificationMethod(key1.id,
            relationships: {VerificationRelationship.authentication});
        final res2 = await controller.addVerificationMethod(key2.id,
            relationships: {VerificationRelationship.assertionMethod});
        final vmId1 = res1.verificationMethodId;
        final vmId2 = res2.verificationMethodId;

        final data = Uint8List.fromList('Test data'.codeUnits);

        // Act
        final sig1 = await controller.sign(data, vmId1);
        final sig2 = await controller.sign(data, vmId2);

        final valid1 = await controller.verify(data, sig1, vmId1);
        final valid2 = await controller.verify(data, sig2, vmId2);

        // Assert
        expect(valid1, isTrue);
        expect(valid2, isTrue);
        expect(sig1, isNot(equals(sig2)));
      });
    });

    group('Verification method purposes', () {
      test('should track all verification method purposes in controller',
          () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'auth-purpose');
        final kaKey = await wallet.generateKey(
            keyId: 'ka-purpose', keyType: KeyType.ed25519);
        final ciKey = await wallet.generateKey(keyId: 'ci-purpose');
        final cdKey = await wallet.generateKey(keyId: 'cd-purpose');
        final amKey = await wallet.generateKey(keyId: 'am-purpose');

        // Add verification methods and set purposes
        final resAuth = await controller.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});
        final resKa = await controller.addVerificationMethod(kaKey.id,
            relationships: {VerificationRelationship.keyAgreement});
        final resCi = await controller.addVerificationMethod(ciKey.id,
            relationships: {VerificationRelationship.capabilityInvocation});
        final resCd = await controller.addVerificationMethod(cdKey.id,
            relationships: {VerificationRelationship.capabilityDelegation});
        final resAm = await controller.addVerificationMethod(amKey.id,
            relationships: {VerificationRelationship.assertionMethod});

        final vmIds = [
          resAuth.verificationMethodId,
          resKa.relationships[VerificationRelationship.keyAgreement]!,
          resCi.verificationMethodId,
          resCd.verificationMethodId,
          resAm.verificationMethodId
        ];

        // Assert - Controller tracks all purposes
        expect(controller.authentication, contains(vmIds[0]));
        expect(controller.keyAgreement, contains(vmIds[1]));
        expect(controller.capabilityInvocation, contains(vmIds[2]));
        expect(controller.capabilityDelegation, contains(vmIds[3]));
        expect(controller.assertionMethod, contains(vmIds[4]));

        // Act - Get document
        final document = await controller.getDidDocument();

        // Assert - did:peer document only includes authentication and keyAgreement
        expect(
            document.authentication.any((ref) => ref.id == vmIds[0]), isTrue);
        expect(document.keyAgreement.any((ref) => ref.id == vmIds[1]), isTrue);

        // did:peer doesn't include these in the document
        expect(document.capabilityInvocation, isEmpty);
        expect(document.capabilityDelegation, isEmpty);
        expect(document.assertionMethod, isEmpty);
      });

      test('should remove verification method purposes', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'remove-purpose-1');
        final key2 = await wallet.generateKey(keyId: 'remove-purpose-2');
        final res1 =
            await controller.addVerificationMethod(key1.id, relationships: {});
        final res2 =
            await controller.addVerificationMethod(key2.id, relationships: {});
        final vmId1 = res1.verificationMethodId;
        final vmId2 = res2.verificationMethodId;

        // Add multiple purposes
        await controller.addAuthentication(vmId1);
        await controller.addAuthentication(vmId2);
        await controller.addAssertionMethod(vmId1);
        await controller.addCapabilityInvocation(vmId1);

        // Assert initial state
        expect(controller.authentication.length, 2);
        expect(controller.assertionMethod.length, 1);
        expect(controller.capabilityInvocation.length, 1);

        // Act - Remove vmId1 from authentication
        await controller.removeAuthentication(vmId1);
        await controller.removeAssertionMethod(vmId1);

        // Assert - Controller state updated
        expect(controller.authentication, [vmId2]);
        expect(controller.assertionMethod, isEmpty);
        expect(controller.capabilityInvocation, [vmId1]);

        // Get document - should still work with vmId2 in authentication
        final document = await controller.getDidDocument();
        expect(document.authentication.length, 1);
        // For did:peer:0 (single auth key), authentication contains the full DID
        expect(document.authentication[0].id, document.id);
      });
    });

    group('DID signer integration', () {
      test('should get DID signer', () async {
        // Arrange
        final key = await wallet.generateKey(keyId: 'signer-key');
        final result = await controller.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.authentication});
        final vmId = result.verificationMethodId;

        // Act
        final signer = await controller.getSigner(vmId);

        // Assert
        expect(signer.didKeyId, equals(vmId));
        expect(signer.signatureScheme, isNotNull);
        expect(signer.did,
            startsWith('did:peer:0')); // Single auth key generates peer:0
      });

      test('should specify signature scheme for signer', () async {
        // Arrange
        final key = await wallet.generateKey(
          keyId: 'signer-scheme-key',
          keyType: KeyType.p256,
        );
        final result = await controller.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.authentication});
        final vmId = result.verificationMethodId;

        // Act
        final signer = await controller.getSigner(
          vmId,
          signatureScheme: SignatureScheme.ecdsa_p256_sha256,
        );

        // Assert
        expect(signer.signatureScheme, SignatureScheme.ecdsa_p256_sha256);
      });
    });

    group('Key retrieval', () {
      test('should retrieve DID key pair', () async {
        // Arrange
        final key = await wallet.generateKey(keyId: 'retrieve-key');
        final result = await controller.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.authentication});
        final vmId = result.verificationMethodId;

        // Act
        final didKeyPair = await controller.getKey(vmId);

        // Assert
        expect(didKeyPair.keyPair.id, equals(key.id));
        expect(didKeyPair.verificationMethodId, equals(vmId));
        expect(didKeyPair.didDocument?.id,
            startsWith('did:peer:0')); // Single auth key generates peer:0
      });
    });

    group('Context verification', () {
      test('should use multikey context for did:peer:2', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'context-key-1');
        final key2 = await wallet.generateKey(
            keyId: 'context-key-2', keyType: KeyType.ed25519);

        await controller.addVerificationMethod(key1.id,
            relationships: {VerificationRelationship.authentication});
        await controller.addVerificationMethod(key2.id,
            relationships: {VerificationRelationship.keyAgreement});

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(
            document.context
                .hasUrlContext(Uri.parse('https://www.w3.org/ns/did/v1')),
            isTrue);
        expect(
            document.context.hasUrlContext(
                Uri.parse('https://w3id.org/security/multikey/v1')),
            isTrue);
      });
    });

    group('DID generation', () {
      test('should generate did:peer:0 for single auth key without service',
          () async {
        // Arrange
        final key = await wallet.generateKey(keyId: 'peer0-key');
        await controller.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.authentication});

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.id, startsWith('did:peer:0'));
      });

      test('should generate did:peer:2 for multiple keys', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'peer2-key-1');
        final key2 = await wallet.generateKey(keyId: 'peer2-key-2');

        await controller.addVerificationMethod(key1.id,
            relationships: {VerificationRelationship.authentication});
        await controller.addVerificationMethod(key2.id,
            relationships: {VerificationRelationship.authentication});

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.id, startsWith('did:peer:2'));
      });

      test('should generate did:peer:2 with service endpoint', () async {
        // Arrange
        final key = await wallet.generateKey(keyId: 'peer2-service-key');
        await controller.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.authentication});

        final endpoint = ServiceEndpoint(
          id: '#service',
          type: 'TestService',
          serviceEndpoint: const StringEndpoint('https://example.com'),
        );
        await controller.addServiceEndpoint(endpoint);

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.id, startsWith('did:peer:2'));
        expect(document.id, contains('.S')); // Service encoding in DID
      });
    });
  });
}
