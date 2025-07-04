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
        final key1 =
            await wallet.generateKey(keyId: 'key-1', keyType: KeyType.p256);
        final key2 =
            await wallet.generateKey(keyId: 'key-2', keyType: KeyType.p256);
        final key3 =
            await wallet.generateKey(keyId: 'key-3', keyType: KeyType.p256);

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
          wallet.generateKey(keyId: 'idx-key-1', keyType: KeyType.p256),
          wallet.generateKey(keyId: 'idx-key-2', keyType: KeyType.p256),
          wallet.generateKey(keyId: 'idx-key-3', keyType: KeyType.p256),
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
      test(
          'generates a valid did:peer:2 document with auth, agreement, and service',
          () async {
        // Generate key
        final key = await wallet.generateKey(keyType: KeyType.ed25519);

        // Add verification method for both auth and key agreement
        await controller.addVerificationMethod(key.id, relationships: {
          VerificationRelationship.authentication,
          VerificationRelationship.keyAgreement
        });

        // Add service endpoint
        final serviceEndpoint = ServiceEndpoint(
          id: '#service-1',
          type: 'DIDCommMessaging',
          serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
        );
        await controller.addServiceEndpoint(serviceEndpoint);

        // Get DID Document
        final didDocument = await controller.getDidDocument();
        expect(isPeerDID(didDocument.id), isTrue);

        // Verify DID
        expect(didDocument.id, startsWith('did:peer:2'));

        // Verify verification methods
        expect(didDocument.verificationMethod, hasLength(2));
        expect(didDocument.verificationMethod[0].id, '#key-1');
        expect(didDocument.verificationMethod[0].type, 'Multikey');
        expect(didDocument.verificationMethod[1].id, '#key-2');
        expect(didDocument.verificationMethod[1].type, 'Multikey');

        // Verify verification relationships
        expect(didDocument.authentication.map((e) => e.id), ['#key-1']);
        expect(didDocument.keyAgreement.map((e) => e.id), ['#key-2']);

        // Verify service endpoint
        expect(didDocument.service, hasLength(1));
        expect(didDocument.service[0].id, '#service-1');
        expect(didDocument.service[0].type, 'DIDCommMessaging');
        expect((didDocument.service[0].serviceEndpoint as StringEndpoint).url,
            'https://example.com/endpoint');

        // Verify resolution
        final resolvedDoc = DidPeer.resolve(didDocument.id);
        expect(resolvedDoc.toJson(), didDocument.toJson());
      });

      test('should throw error when no keys are added', () async {
        // Act & Assert
        expect(
          () => controller.getDidDocument(),
          throwsA(
            isA<SsiException>()
                .having(
                  (e) => e.message,
                  'message',
                  'At least one key must be added before creating did:peer document',
                )
                .having(
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
        final auth1 =
            await wallet.generateKey(keyId: 'auth-1', keyType: KeyType.p256);
        final auth2 =
            await wallet.generateKey(keyId: 'auth-2', keyType: KeyType.p256);
        final auth3 =
            await wallet.generateKey(keyId: 'auth-3', keyType: KeyType.p256);

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
        expect(isPeerDID(document.id), isTrue);

        // Assert
        expect(document.id, startsWith('did:peer:2'));
        expect(document.verificationMethod.length, 3);
        expect(document.authentication.length, 3);
        expect(document.authentication.map((ref) => ref.id).toList(),
            containsAll([vmId1, vmId2, vmId3]));
      });
    });

    group('Service endpoints', () {
      test('should add multiple service endpoints', () async {
        // Arrange
        final authKey = await wallet.generateKey(
            keyId: 'multi-service-key', keyType: KeyType.p256);
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
        expect(isPeerDID(document.id), isTrue);

        // Assert
        expect(document.id, startsWith('did:peer:2'));
        expect(document.service.length, 2);
        expect(document.service.map((s) => s.id).toList(),
            containsAll(['#service-1', '#service-2']));
      });

      test('should remove service endpoint', () async {
        // Arrange
        final authKey = await wallet.generateKey(
            keyId: 'remove-service-key', keyType: KeyType.p256);
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
        expect(isPeerDID(docBefore.id), isTrue);

        await controller.removeServiceEndpoint('#service-to-remove');
        final docAfter = await controller.getDidDocument();
        expect(isPeerDID(docAfter.id), isTrue);

        // Assert
        expect(docBefore.id, startsWith('did:peer:2'));
        expect(docBefore.service.length, 1);
        expect(docAfter.id, startsWith('did:peer:0'));
        expect(docAfter.service.length, 0);
      });

      test('should throw error when adding duplicate service endpoint',
          () async {
        // Arrange
        final authKey = await wallet.generateKey(
            keyId: 'dup-service-key', keyType: KeyType.p256);
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
        final authKey = await wallet.generateKey(
            keyId: 'sign-auth-key', keyType: KeyType.p256);
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
        final key1 = await wallet.generateKey(
            keyId: 'sign-key-1', keyType: KeyType.p256);
        final key2 = await wallet.generateKey(
            keyId: 'sign-key-2', keyType: KeyType.p256);

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
        final authKey = await wallet.generateKey(
            keyId: 'auth-purpose', keyType: KeyType.p256);
        final kaKey = await wallet.generateKey(
            keyId: 'ka-purpose', keyType: KeyType.ed25519);
        final ciKey = await wallet.generateKey(
            keyId: 'ci-purpose', keyType: KeyType.p256);
        final cdKey = await wallet.generateKey(
            keyId: 'cd-purpose', keyType: KeyType.p256);
        final amKey = await wallet.generateKey(
            keyId: 'am-purpose', keyType: KeyType.p256);

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
        expect(isPeerDID(document.id), isTrue);

        // Assert
        expect(document.id, startsWith('did:peer:2'));
        expect(
            document.authentication.any((ref) => ref.id == vmIds[0]), isTrue);
        expect(document.keyAgreement.any((ref) => ref.id == vmIds[1]), isTrue);
        expect(document.capabilityInvocation.any((ref) => ref.id == vmIds[2]),
            isTrue);
        expect(document.capabilityDelegation.any((ref) => ref.id == vmIds[3]),
            isTrue);
        expect(
            document.assertionMethod.any((ref) => ref.id == vmIds[4]), isTrue);
      });

      test('should remove verification method purposes', () async {
        // Arrange
        final key1 = await wallet.generateKey(
            keyId: 'remove-purpose-1', keyType: KeyType.p256);
        final key2 = await wallet.generateKey(
            keyId: 'remove-purpose-2', keyType: KeyType.p256);
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
        expect(isPeerDID(document.id), isTrue);
        expect(document.id, startsWith('did:peer:2'));
        expect(document.authentication.length, 1);
      });
    });

    group('DID signer integration', () {
      test('should get DID signer', () async {
        // Arrange
        final key = await wallet.generateKey(
            keyId: 'signer-key', keyType: KeyType.p256);
        final result = await controller.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.authentication});
        final vmId = result.verificationMethodId;

        // Act
        final signer = await controller.getSigner(vmId);

        // Assert
        expect(signer.keyId, equals(vmId));
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
        final key = await wallet.generateKey(
            keyId: 'retrieve-key', keyType: KeyType.p256);
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
        final key1 = await wallet.generateKey(
            keyId: 'context-key-1', keyType: KeyType.p256);
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
      test('generates a valid did:peer:0 document', () async {
        // Generate key
        final authKey = await wallet.generateKey(keyType: KeyType.ed25519);

        // Add verification method and assign purpose
        await controller.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        // Get DID Document
        final didDocument = await controller.getDidDocument();
        expect(isPeerDID(didDocument.id), isTrue);

        // Verify DID
        expect(didDocument.id, startsWith('did:peer:0'));

        // Verify verification method
        expect(didDocument.verificationMethod, hasLength(1));
        expect(didDocument.verificationMethod[0].id, didDocument.id);
        expect(didDocument.verificationMethod[0].type, 'Multikey');

        // Verify verification relationships from generator
        expect(didDocument.authentication.map((e) => e.id), [didDocument.id]);
        expect(didDocument.assertionMethod.map((e) => e.id), [didDocument.id]);
        expect(didDocument.capabilityInvocation.map((e) => e.id),
            [didDocument.id]);
        expect(didDocument.capabilityDelegation.map((e) => e.id),
            [didDocument.id]);
        expect(didDocument.keyAgreement, isEmpty);

        // Verify resolution
        final resolvedDoc = DidPeer.resolve(didDocument.id);

        // The resolved document for did:peer:0 will have an additional keyAgreement
        // derived from the authentication key.
        expect(resolvedDoc.id, didDocument.id);
        final authVmId = resolvedDoc.authentication.first.id;
        expect(authVmId, '${didDocument.id}#${didDocument.id.substring(10)}');
        expect(resolvedDoc.keyAgreement, isNotNull);
        expect(resolvedDoc.keyAgreement, hasLength(1));
        expect(resolvedDoc.verificationMethod, hasLength(2));
      });

      test('should generate did:peer:2 for multiple keys', () async {
        // Arrange
        final key1 = await wallet.generateKey(
            keyId: 'peer2-key-1', keyType: KeyType.p256);
        final key2 = await wallet.generateKey(
            keyId: 'peer2-key-2', keyType: KeyType.p256);

        await controller.addVerificationMethod(key1.id,
            relationships: {VerificationRelationship.authentication});
        await controller.addVerificationMethod(key2.id,
            relationships: {VerificationRelationship.authentication});

        // Act
        final document = await controller.getDidDocument();
        expect(isPeerDID(document.id), isTrue);

        // Assert
        expect(document.id, startsWith('did:peer:2'));
      });

      test(
          'generates a did:peer:2 document when a service is added, even with one auth key',
          () async {
        // Generate key
        final authKey = await wallet.generateKey(keyType: KeyType.ed25519);

        // Add verification method and assign purpose
        await controller.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        // Add service endpoint
        final serviceEndpoint = ServiceEndpoint(
          id: '#service-1',
          type: 'DIDCommMessaging',
          serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
        );
        await controller.addServiceEndpoint(serviceEndpoint);

        // Get DID Document
        final didDocument = await controller.getDidDocument();
        expect(isPeerDID(didDocument.id), isTrue);

        // Verify DID is did:peer:2 because a service was added
        expect(didDocument.id, startsWith('did:peer:2'));
        expect(didDocument.id, contains('.S')); // Service encoding in DID

        // Verify resolution
        final resolvedDoc = DidPeer.resolve(didDocument.id);
        expect(resolvedDoc.toJson(), didDocument.toJson());
      });

      test('generates a valid did:peer:0 document with secp256k1 key',
          () async {
        // Arrange
        // Use Bip32Wallet for secp256k1 keys
        final seed = Uint8List(32); // A dummy seed for testing
        final bip32Wallet = Bip32Wallet.fromSeed(seed);
        final store = InMemoryDidStore();
        final controller = DidPeerController(
          store: store,
          wallet: bip32Wallet,
        );
        const derivationPath = "m/44'/0'/0'/0/0";
        final authKey = await bip32Wallet.generateKey(keyId: derivationPath);

        // Add verification method and assign purpose
        await controller.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        // Act
        final didDocument = await controller.getDidDocument();
        expect(isPeerDID(didDocument.id), isTrue);

        // Assert on generated document
        expect(didDocument.id, startsWith('did:peer:0'));
        expect(didDocument.verificationMethod, hasLength(1));
        expect(didDocument.verificationMethod[0].id, didDocument.id);
        expect(didDocument.verificationMethod[0].type, 'Multikey');
        expect(didDocument.authentication.map((e) => e.id), [didDocument.id]);

        // Verify resolution and content
        final resolvedDoc = DidPeer.resolve(didDocument.id);
        expect(resolvedDoc.id, didDocument.id);
        expect(resolvedDoc.verificationMethod, hasLength(1));
        expect(resolvedDoc.verificationMethod[0].type, 'Multikey');
        final keyPart = didDocument.id.substring(11);
        final expectedVmId = '${didDocument.id}#z$keyPart';
        expect(resolvedDoc.verificationMethod[0].id, expectedVmId);
        expect(resolvedDoc.authentication.map((e) => e.id).first, expectedVmId);
        expect(resolvedDoc.keyAgreement, isEmpty);
      });
    });
  });
}
