import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidPeerManager', () {
    late Wallet wallet;
    late DidStore store;
    late DidPeerManager manager;

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      store = InMemoryDidStore();
      manager = DidPeerManager(
        store: store,
        wallet: wallet,
        preferredNumalgo: DidPeerType.peer0,
      );
      await manager.init();
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
            await manager.addVerificationMethod(key1.id, relationships: {});
        final res2 =
            await manager.addVerificationMethod(key2.id, relationships: {});
        final res3 =
            await manager.addVerificationMethod(key3.id, relationships: {});

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
              await manager.addVerificationMethod(key.id, relationships: {});
          vmIds.add(res.verificationMethodId);
        }

        // Assert
        expect(vmIds, ['#key-1', '#key-2', '#key-3']);
      });
    });

    group('DID document/controller cross-checks', () {
      test('keyAgreement id in DID document matches keypair in controller',
          () async {
        // Generate key
        final key = await wallet.generateKey(keyType: KeyType.ed25519);

        // Add verification method for both auth and key agreement
        await manager.addVerificationMethod(key.id, relationships: {
          VerificationRelationship.authentication,
          VerificationRelationship.keyAgreement
        });

        // Add service endpoint
        final serviceEndpoint = ServiceEndpoint(
          id: '#service-1',
          type: const StringServiceType('DIDCommMessaging'),
          serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
        );
        await manager.addServiceEndpoint(serviceEndpoint);

        // Get DID Document
        final didDocument = await manager.getDidDocument();
        expect(isPeerDID(didDocument.id), isTrue);
        expect(didDocument.id, startsWith('did:peer:2'));

        // Cross-check: get key agreement id from doc and retrieve keypair from manager
        final keyAgreementId = didDocument.keyAgreement.first.id;
        final didKeyPair = await manager.getKey(keyAgreementId);
        expect(didKeyPair.keyPair.id, equals(key.id));
        expect(didKeyPair.verificationMethodId, equals(keyAgreementId));
      });
    });

    group('getDidDocument', () {
      test(
          'generates a valid did:peer:2 document with auth, agreement, and service',
          () async {
        // Generate key
        final key = await wallet.generateKey(keyType: KeyType.ed25519);

        // Add verification method for both auth and key agreement
        await manager.addVerificationMethod(key.id, relationships: {
          VerificationRelationship.authentication,
          VerificationRelationship.keyAgreement
        });

        // Add service endpoint
        final serviceEndpoint = ServiceEndpoint(
          id: '#service-1',
          type: const StringServiceType('DIDCommMessaging'),
          serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
        );
        await manager.addServiceEndpoint(serviceEndpoint);

        // Get DID Document
        final didDocument = await manager.getDidDocument();
        expect(isPeerDID(didDocument.id), isTrue);

        // Verify DID
        expect(didDocument.id, startsWith('did:peer:2'));

        // Verify verification methods
        expect(didDocument.verificationMethod, hasLength(2));
        expect(didDocument.verificationMethod[0].id, '${didDocument.id}#key-1');
        expect(didDocument.verificationMethod[0].type, 'Multikey');
        expect(didDocument.verificationMethod[1].id, '${didDocument.id}#key-2');
        expect(didDocument.verificationMethod[1].type, 'Multikey');

        // Verify verification relationships
        expect(didDocument.authentication.map((e) => e.id).toList(),
            ['${didDocument.id}#key-1']);
        expect(didDocument.keyAgreement.map((e) => e.id).toList(),
            ['${didDocument.id}#key-2']);

        // Cross-check: get key agreement id from doc and retrieve keypair from manager
        final keyAgreementId = didDocument.keyAgreement.first.id;
        final didKeyPair = await manager.getKey(keyAgreementId);
        expect(didKeyPair.keyPair.id, equals(key.id));
        expect(didKeyPair.verificationMethodId, equals(keyAgreementId));

        // Verify service endpoint
        expect(didDocument.service, hasLength(1));
        expect(didDocument.service[0].id, '#service-1');
        expect(didDocument.service[0].type,
            const StringServiceType('DIDCommMessaging'));
        expect((didDocument.service[0].serviceEndpoint as StringEndpoint).url,
            'https://example.com/endpoint');

        // Verify resolution
        final resolvedDoc = DidPeer.resolve(didDocument.id);
        expect(resolvedDoc.toJson(), didDocument.toJson());
      });

      test('should throw error when no keys are added', () async {
        // Act & Assert
        expect(
          () => manager.getDidDocument(),
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
        final res1 = await manager.addVerificationMethod(auth1.id,
            relationships: {VerificationRelationship.authentication});
        final res2 = await manager.addVerificationMethod(auth2.id,
            relationships: {VerificationRelationship.authentication});
        final res3 = await manager.addVerificationMethod(auth3.id,
            relationships: {VerificationRelationship.authentication});
        final vmId1 = res1.verificationMethodId;
        final vmId2 = res2.verificationMethodId;
        final vmId3 = res3.verificationMethodId;

        // Act
        final document = await manager.getDidDocument();
        expect(isPeerDID(document.id), isTrue);

        // Assert
        expect(document.id, startsWith('did:peer:2'));
        expect(document.verificationMethod.length, 3);
        expect(document.authentication.length, 3);
        expect(
          document.authentication.map((ref) => ref.id).toList(),
          containsAll([
            '${document.id}$vmId1',
            '${document.id}$vmId2',
            '${document.id}$vmId3',
          ]),
        );
      });
    });

    group('Service endpoints', () {
      test('should add multiple service endpoints', () async {
        // Arrange
        final authKey = await wallet.generateKey(
            keyId: 'multi-service-key', keyType: KeyType.p256);
        await manager.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        final endpoint1 = ServiceEndpoint(
          id: '#service-1',
          type: const StringServiceType('MessagingService'),
          serviceEndpoint:
              const StringEndpoint('https://example.com/messaging'),
        );

        final endpoint2 = ServiceEndpoint(
          id: '#service-2',
          type: const StringServiceType('CredentialService'),
          serviceEndpoint: const MapEndpoint({
            'uri': 'https://example.com/credentials',
            'accept': ['application/json'],
          }),
        );

        // Act
        await manager.addServiceEndpoint(endpoint1);
        await manager.addServiceEndpoint(endpoint2);
        final document = await manager.getDidDocument();
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
        await manager.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        final endpoint = ServiceEndpoint(
          id: '#service-to-remove',
          type: const StringServiceType('TestService'),
          serviceEndpoint: const StringEndpoint('https://example.com'),
        );

        // Act
        await manager.addServiceEndpoint(endpoint);
        final docBefore = await manager.getDidDocument();
        expect(isPeerDID(docBefore.id), isTrue);

        await manager.removeServiceEndpoint('#service-to-remove');
        final docAfter = await manager.getDidDocument();
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
        await manager.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        final endpoint = ServiceEndpoint(
          id: '#duplicate-service',
          type: const StringServiceType('TestService'),
          serviceEndpoint: const StringEndpoint('https://example.com'),
        );

        // Act
        await manager.addServiceEndpoint(endpoint);

        // Assert
        expect(
          () => manager.addServiceEndpoint(endpoint),
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
        final result = await manager.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});
        final vmId = result.verificationMethodId;

        final data = Uint8List.fromList('Hello, DID Peer!'.codeUnits);

        // Act
        final signature = await manager.sign(data, vmId);
        final isValid = await manager.verify(data, signature, vmId);

        // Assert
        expect(isValid, isTrue);
      });

      test('should sign and verify with different keys', () async {
        // Arrange
        final key1 = await wallet.generateKey(
            keyId: 'sign-key-1', keyType: KeyType.p256);
        final key2 = await wallet.generateKey(
            keyId: 'sign-key-2', keyType: KeyType.p256);

        final res1 = await manager.addVerificationMethod(key1.id,
            relationships: {VerificationRelationship.authentication});
        final res2 = await manager.addVerificationMethod(key2.id,
            relationships: {VerificationRelationship.assertionMethod});
        final vmId1 = res1.verificationMethodId;
        final vmId2 = res2.verificationMethodId;

        final data = Uint8List.fromList('Test data'.codeUnits);

        // Act
        final sig1 = await manager.sign(data, vmId1);
        final sig2 = await manager.sign(data, vmId2);

        final valid1 = await manager.verify(data, sig1, vmId1);
        final valid2 = await manager.verify(data, sig2, vmId2);

        // Assert
        expect(valid1, isTrue);
        expect(valid2, isTrue);
        expect(sig1, isNot(equals(sig2)));
      });
    });

    group('Verification method purposes', () {
      test('should track all verification method purposes in manager',
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
        final resAuth = await manager.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});
        final resKa = await manager.addVerificationMethod(kaKey.id,
            relationships: {VerificationRelationship.keyAgreement});
        final resCi = await manager.addVerificationMethod(ciKey.id,
            relationships: {VerificationRelationship.capabilityInvocation});
        final resCd = await manager.addVerificationMethod(cdKey.id,
            relationships: {VerificationRelationship.capabilityDelegation});
        final resAm = await manager.addVerificationMethod(amKey.id,
            relationships: {VerificationRelationship.assertionMethod});

        final vmIds = [
          resAuth.verificationMethodId,
          resKa.relationships[VerificationRelationship.keyAgreement]!,
          resCi.verificationMethodId,
          resCd.verificationMethodId,
          resAm.verificationMethodId
        ];

        // Assert - Controller tracks all purposes
        expect(manager.authentication, contains(vmIds[0]));
        expect(manager.keyAgreement, contains(vmIds[1]));
        expect(manager.capabilityInvocation, contains(vmIds[2]));
        expect(manager.capabilityDelegation, contains(vmIds[3]));
        expect(manager.assertionMethod, contains(vmIds[4]));

        // Act - Get document
        final document = await manager.getDidDocument();
        expect(isPeerDID(document.id), isTrue);

        // Assert
        expect(document.id, startsWith('did:peer:2'));
        expect(
            document.authentication
                .any((ref) => ref.id == '${document.id}${vmIds[0]}'),
            isTrue);
        expect(
            document.keyAgreement
                .any((ref) => ref.id == '${document.id}${vmIds[1]}'),
            isTrue);
        expect(
            document.capabilityInvocation
                .any((ref) => ref.id == '${document.id}${vmIds[2]}'),
            isTrue);
        expect(
            document.capabilityDelegation
                .any((ref) => ref.id == '${document.id}${vmIds[3]}'),
            isTrue);
        expect(
            document.assertionMethod
                .any((ref) => ref.id == '${document.id}${vmIds[4]}'),
            isTrue);
      });

      test('should remove verification method purposes', () async {
        // Arrange
        final key1 = await wallet.generateKey(
            keyId: 'remove-purpose-1', keyType: KeyType.p256);
        final key2 = await wallet.generateKey(
            keyId: 'remove-purpose-2', keyType: KeyType.p256);
        final res1 =
            await manager.addVerificationMethod(key1.id, relationships: {});
        final res2 =
            await manager.addVerificationMethod(key2.id, relationships: {});
        final vmId1 = res1.verificationMethodId;
        final vmId2 = res2.verificationMethodId;

        // Add multiple purposes
        await manager.addAuthentication(vmId1);
        await manager.addAuthentication(vmId2);
        await manager.addAssertionMethod(vmId1);
        await manager.addCapabilityInvocation(vmId1);

        // Assert initial state
        expect(manager.authentication.length, 2);
        expect(manager.assertionMethod.length, 1);
        expect(manager.capabilityInvocation.length, 1);

        // Act - Remove vmId1 from authentication
        await manager.removeAuthentication(vmId1);
        await manager.removeAssertionMethod(vmId1);

        // Assert - Controller state updated
        expect(manager.authentication, [vmId2]);
        expect(manager.assertionMethod, isEmpty);
        expect(manager.capabilityInvocation, [vmId1]);

        // Get document - should still work with vmId2 in authentication
        final document = await manager.getDidDocument();
        expect(isPeerDID(document.id), isTrue);
        expect(document.id, startsWith('did:peer:2'));
        expect(document.authentication.length, 1);
      });

      test('should create ONE verification method shared across purposes',
          () async {
        final key = await wallet.generateKey(
            keyId: 'multi-purpose-key', keyType: KeyType.p256);

        final result =
            await manager.addVerificationMethod(key.id, relationships: {
          VerificationRelationship.authentication,
          VerificationRelationship.assertionMethod,
        });

        final authVmId =
            result.relationships[VerificationRelationship.authentication];
        final assertVmId =
            result.relationships[VerificationRelationship.assertionMethod];

        expect(authVmId, isNotNull);
        expect(assertVmId, isNotNull);
        // One-to-one: same VM for both purposes
        expect(authVmId, equals(assertVmId),
            reason: 'Both purposes should share one verification method ID');

        final storeAuth = await store.authentication;
        final storeAssert = await store.assertionMethod;

        expect(storeAuth, [authVmId]);
        expect(storeAssert, [authVmId]); // same VM ID

        final allVmIds = await store.verificationMethodIds;
        expect(allVmIds, hasLength(1)); // just 1 VM
        expect(allVmIds, contains(authVmId));

        final doc = await manager.getDidDocument();
        // With 1 VM, did:peer:0 is generated — VM IDs are fully qualified.
        expect(doc.verificationMethod, hasLength(1));
        expect(doc.authentication, hasLength(1));
        expect(doc.assertionMethod, hasLength(1));
        // The important check: auth and assertion reference the SAME VM.
        expect(doc.authentication.first.id, doc.assertionMethod.first.id);
      });

      test('should maintain verification method order across manager instances',
          () async {
        // Arrange: First manager instance
        final key1 = await wallet.generateKey(
            keyId: 'order-key-1', keyType: KeyType.ed25519);
        final key2 = await wallet.generateKey(
            keyId: 'order-key-2', keyType: KeyType.p256);

        // Act: Add keys in a specific order
        final res1 =
            await manager.addVerificationMethod(key1.id, relationships: {
          VerificationRelationship.authentication,
          VerificationRelationship.keyAgreement,
        });
        final res2 = await manager.addVerificationMethod(key2.id,
            relationships: {VerificationRelationship.authentication});

        final authVmId1 =
            res1.relationships[VerificationRelationship.authentication]!;
        final kaVmId1 =
            res1.relationships[VerificationRelationship.keyAgreement]!;
        final authVmId2 =
            res2.relationships[VerificationRelationship.authentication]!;

        // Assert: Check the state of the first manager
        final doc1 = await manager.getDidDocument();
        expect(doc1.id, startsWith('did:peer:2'));
        expect(doc1.verificationMethod, hasLength(3));
        expect(doc1.verificationMethod.map((vm) => vm.id).toList(), [
          '${doc1.id}$authVmId1',
          '${doc1.id}$kaVmId1',
          '${doc1.id}$authVmId2'
        ]);
        expect(doc1.authentication.map((ref) => ref.id).toList(),
            ['${doc1.id}$authVmId1', '${doc1.id}$authVmId2']);
        expect(doc1.keyAgreement.map((ref) => ref.id).toList(),
            ['${doc1.id}$kaVmId1']);

        // Compare resolved doc with originally created doc
        final resolvedDoc1 = DidPeer.resolve(doc1.id);
        expect(resolvedDoc1.toJson(), doc1.toJson());

        // Arrange: Second manager instance with the same store
        final manager2 = DidPeerManager(
            store: store, wallet: wallet, preferredNumalgo: DidPeerType.peer0);
        await manager2.init();

        // Act: Get document from the second manager
        final doc2 = await manager2.getDidDocument();

        // Assert: Ensure the second manager produces the identical document
        expect(doc2.id, doc1.id,
            reason: 'DIDs from both managers should match');
        expect(doc2.toJson(), doc1.toJson(),
            reason: 'DID documents from both managers should match');
      });
    });

    group('DID signer integration', () {
      test('should get DID signer', () async {
        // Arrange
        final key = await wallet.generateKey(
            keyId: 'signer-key', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.authentication});
        final vmId = result.verificationMethodId;

        // Act
        final signer = await manager.getSigner(vmId);

        // Assert
        expect(signer.keyId, equals('${signer.did}$vmId'));
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
        final result = await manager.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.authentication});
        final vmId = result.verificationMethodId;

        // Act
        final signer = await manager.getSigner(
          vmId,
          signatureScheme: SignatureScheme.ecdsa_p256_sha256,
        );

        // Assert
        expect(signer.signatureScheme, SignatureScheme.ecdsa_p256_sha256);
      });

      test(
          'normalizes fragment-only verificationMethodId to full DID URL and uses full ID in proofs',
          () async {
        final key = await wallet.generateKey(keyType: KeyType.ed25519);
        final result = await manager.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.authentication});
        final vmIdFragment = result.verificationMethodId; // e.g. '#key-1'

        final signer = await manager.getSigner(vmIdFragment);

        // signer.keyId should now be fully qualified DID + fragment
        expect(signer.keyId, '${signer.did}$vmIdFragment');

        // signer.did should be a did:peer:0 (single auth key)
        expect(signer.did.startsWith('did:peer:0'), isTrue);

        // signer.didKeyId should equal keyId (already fully qualified)
        expect(signer.didKeyId, signer.keyId);

        // Generate a simple credential using this signer and assert proof.verificationMethod is fully-qualified
        final unsignedCredential = MutableVcDataModelV1(
          context: MutableJsonLdContext.fromJson([
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/data-integrity/v2'
          ]),
          id: Uri.parse('uuid:test-normalization'),
          type: {'VerifiableCredential'},
          credentialSubject: [
            MutableCredentialSubject({'id': signer.did, 'test': 'value'})
          ],
          issuanceDate: DateTime.now(),
          issuer: Issuer.uri(signer.did),
        );

        final proofGenerator = DataIntegrityEddsaJcsGenerator(signer: signer);
        final issued = await LdVcDm1Suite().issue(
          unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
          proofGenerator: proofGenerator,
        );

        final proof = issued.toJson()['proof'] as Map<String, dynamic>;
        expect(proof['verificationMethod'], signer.keyId);
        expect(proof['verificationMethod'], startsWith(signer.did));
      });

      test('keeps fully-qualified verificationMethodId unchanged', () async {
        final key1 = await wallet.generateKey(keyType: KeyType.p256);
        final key2 = await wallet.generateKey(keyType: KeyType.p256);
        await manager.addVerificationMethod(key1.id,
            relationships: {VerificationRelationship.authentication});
        await manager.addVerificationMethod(key2.id,
            relationships: {VerificationRelationship.authentication});
        final didDocument = await manager.getDidDocument(); // did:peer:2
        final vmFull = '${didDocument.id}#key-1';

        // getSigner should not double prefix
        final signer = await manager.getSigner(vmFull);
        expect(signer.keyId, vmFull); // keyId is what was passed
        expect(signer.did, didDocument.id);
        expect(signer.didKeyId, vmFull);
      });
    });

    group('Key retrieval', () {
      test('should retrieve DID key pair', () async {
        // Arrange
        final key = await wallet.generateKey(
            keyId: 'retrieve-key', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.authentication});
        final vmId = result.verificationMethodId;

        // Act
        final didKeyPair = await manager.getKey(vmId);

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

        await manager.addVerificationMethod(key1.id,
            relationships: {VerificationRelationship.authentication});
        await manager.addVerificationMethod(key2.id,
            relationships: {VerificationRelationship.keyAgreement});

        // Act
        final document = await manager.getDidDocument();

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
        await manager.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        // Get DID Document
        final didDocument = await manager.getDidDocument();
        expect(isPeerDID(didDocument.id), isTrue);

        // Verify DID
        expect(didDocument.id, startsWith('did:peer:0'));

        // Verify verification method
        expect(didDocument.verificationMethod, hasLength(2));
        final authVmId = didDocument.authentication.first.id;
        expect(authVmId, '${didDocument.id}#${didDocument.id.substring(10)}');

        // Verify verification relationships from generator
        expect(didDocument.authentication, hasLength(1));
        expect(didDocument.assertionMethod, hasLength(1));
        expect(didDocument.capabilityInvocation, hasLength(1));
        expect(didDocument.capabilityDelegation, hasLength(1));
        expect(didDocument.keyAgreement, hasLength(1));

        // Verify resolution
        final resolvedDoc = DidPeer.resolve(didDocument.id);
        expect(resolvedDoc.toJson(), didDocument.toJson());
      });

      test('should generate did:peer:2 for multiple keys', () async {
        // Arrange
        final key1 = await wallet.generateKey(
            keyId: 'peer2-key-1', keyType: KeyType.p256);
        final key2 = await wallet.generateKey(
            keyId: 'peer2-key-2', keyType: KeyType.p256);

        await manager.addVerificationMethod(key1.id,
            relationships: {VerificationRelationship.authentication});
        await manager.addVerificationMethod(key2.id,
            relationships: {VerificationRelationship.authentication});

        // Act
        final document = await manager.getDidDocument();
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
        await manager.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        // Add service endpoint
        final serviceEndpoint = ServiceEndpoint(
          id: '#service-1',
          type: const StringServiceType('DIDCommMessaging'),
          serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
        );
        await manager.addServiceEndpoint(serviceEndpoint);

        // Get DID Document
        final didDocument = await manager.getDidDocument();
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
        final manager = DidPeerManager(
          store: store,
          wallet: bip32Wallet,
          preferredNumalgo: DidPeerType.peer0,
        );
        const derivationPath = "m/44'/0'/0'/0/0";
        final authKey = await bip32Wallet.generateKey(keyId: derivationPath);

        // Add verification method and assign purpose
        await manager.addVerificationMethod(authKey.id,
            relationships: {VerificationRelationship.authentication});

        // Act
        final didDocument = await manager.getDidDocument();
        expect(isPeerDID(didDocument.id), isTrue);

        // Assert on generated document
        expect(didDocument.id, startsWith('did:peer:0'));
        expect(didDocument.verificationMethod, hasLength(1));
        expect(didDocument.verificationMethod[0].type, 'Multikey');
        final keyPart = didDocument.id.substring(11);
        final expectedVmId = '${didDocument.id}#z$keyPart';
        expect(didDocument.verificationMethod[0].id, expectedVmId);
        expect(didDocument.authentication.map((e) => e.id).first, expectedVmId);
        expect(didDocument.keyAgreement, isEmpty);

        // Verify resolution and content
        final resolvedDoc = DidPeer.resolve(didDocument.id);
        expect(resolvedDoc.toJson(), didDocument.toJson());
      });
    });

    // ================================================================
    // One-to-one key → VM mapping tests
    // ================================================================
    group('One-to-one key to VM mapping', () {
      test(
          '1 p256 key with {auth, assertion, capInvoke} → 1 VM shared across all',
          () async {
        final key =
            await wallet.generateKey(keyId: 'p256-3rel', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(
          key.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.assertionMethod,
            VerificationRelationship.capabilityInvocation,
          },
        );

        // All relationships map to the same VM
        final vmId = result.verificationMethodId;
        expect(result.relationships[VerificationRelationship.authentication],
            vmId);
        expect(result.relationships[VerificationRelationship.assertionMethod],
            vmId);
        expect(
            result.relationships[VerificationRelationship.capabilityInvocation],
            vmId);

        final allVmIds = await store.verificationMethodIds;
        expect(allVmIds, hasLength(1));
      });

      test(
          'ed25519 key with {auth, keyAgreement} → 2 VMs: ed25519 + derived X25519',
          () async {
        final key = await wallet.generateKey(
            keyId: 'ed-2rel', keyType: KeyType.ed25519);
        final result = await manager.addVerificationMethod(
          key.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.keyAgreement,
          },
        );

        final authVmId =
            result.relationships[VerificationRelationship.authentication]!;
        final kaVmId =
            result.relationships[VerificationRelationship.keyAgreement]!;
        expect(authVmId, isNot(kaVmId)); // ed25519 vs X25519 = different VMs
        expect(result.verificationMethodId, authVmId); // primary is ed25519

        final allVmIds = await store.verificationMethodIds;
        expect(allVmIds, hasLength(2));
      });
    });

    group('did:peer:2 with single key', () {
      late DidPeerManager peer2Manager;

      setUp(() async {
        final keyStore = InMemoryKeyStore();
        final peer2Wallet = PersistentWallet(keyStore);
        final peer2Store = InMemoryDidStore();
        peer2Manager = DidPeerManager(
          store: peer2Store,
          wallet: peer2Wallet,
          preferredNumalgo: DidPeerType.peer2,
        );
        await peer2Manager.init();
        // Share wallet ref for key generation
        wallet = peer2Wallet;
      });

      test('ed25519 with default relationships produces did:peer:2 with 2 VMs',
          () async {
        final key = await wallet.generateKey(keyType: KeyType.ed25519);
        await peer2Manager.addVerificationMethod(key.id);

        final didDocument = await peer2Manager.getDidDocument();

        // print('--- peer:2 ed25519 default relationships ---');
        // print('DID: ${didDocument.id}');
        // print('VMs: ${didDocument.verificationMethod.length}');
        // for (final vm in didDocument.verificationMethod) {
        //   print('  VM: ${vm.id} (type: ${vm.type})');
        // }
        // print('auth: ${didDocument.authentication.map((e) => e.id).toList()}');
        // print('keyAgreement: ${didDocument.keyAgreement.map((e) => e.id).toList()}');
        // print('assertionMethod: ${didDocument.assertionMethod.map((e) => e.id).toList()}');
        // print('capabilityInvocation: ${didDocument.capabilityInvocation.map((e) => e.id).toList()}');
        // print('capabilityDelegation: ${didDocument.capabilityDelegation.map((e) => e.id).toList()}');
        // print('---');

        expect(didDocument.id, startsWith('did:peer:2'),
            reason: 'peer2 numalgo should produce did:peer:2');
        expect(didDocument.verificationMethod, hasLength(2),
            reason: 'ed25519 + derived X25519 = 2 VMs');
        expect(didDocument.authentication, hasLength(1),
            reason: 'ed25519 key should be in authentication');
        expect(didDocument.assertionMethod, hasLength(1),
            reason: 'ed25519 key should be in assertionMethod');
        expect(didDocument.keyAgreement, hasLength(1),
            reason: 'derived X25519 key should be in keyAgreement');
        expect(didDocument.capabilityInvocation, hasLength(1),
            reason: 'ed25519 key should be in capabilityInvocation');
        expect(didDocument.capabilityDelegation, hasLength(1),
            reason: 'ed25519 key should be in capabilityDelegation');

        final resolvedDoc = DidPeer.resolve(didDocument.id);
        expect(resolvedDoc.id, didDocument.id,
            reason: 'resolved DID should match generated DID');
      });

      test('p256 with default relationships produces did:peer:2 with 1 VM',
          () async {
        final key = await wallet.generateKey(keyType: KeyType.p256);
        await peer2Manager.addVerificationMethod(key.id);

        final didDocument = await peer2Manager.getDidDocument();

        // print('--- peer:2 p256 default relationships ---');
        // print('DID: ${didDocument.id}');
        // print('VMs: ${didDocument.verificationMethod.length}');
        // for (final vm in didDocument.verificationMethod) {
        //   print('  VM: ${vm.id} (type: ${vm.type})');
        // }
        // print('auth: ${didDocument.authentication.map((e) => e.id).toList()}');
        // print('keyAgreement: ${didDocument.keyAgreement.map((e) => e.id).toList()}');
        // print('assertionMethod: ${didDocument.assertionMethod.map((e) => e.id).toList()}');
        // print('capabilityInvocation: ${didDocument.capabilityInvocation.map((e) => e.id).toList()}');
        // print('capabilityDelegation: ${didDocument.capabilityDelegation.map((e) => e.id).toList()}');
        // print('---');

        expect(didDocument.id, startsWith('did:peer:2'),
            reason: 'peer2 numalgo should produce did:peer:2');
        expect(didDocument.verificationMethod, hasLength(1),
            reason: 'p256 uses single VM for all purposes (no derivation)');
        expect(didDocument.authentication, hasLength(1),
            reason: 'p256 key should be in authentication');
        expect(didDocument.assertionMethod, hasLength(1),
            reason: 'p256 key should be in assertionMethod');
        expect(didDocument.keyAgreement, hasLength(1),
            reason: 'p256 supports ECDH, should be in keyAgreement');
        expect(didDocument.capabilityInvocation, hasLength(1),
            reason: 'p256 key should be in capabilityInvocation');
        expect(didDocument.capabilityDelegation, hasLength(1),
            reason: 'p256 key should be in capabilityDelegation');

        final resolvedDoc = DidPeer.resolve(didDocument.id);
        expect(resolvedDoc.id, didDocument.id,
            reason: 'resolved DID should match generated DID');
      });

      test(
          'ed25519 with only keyAgreement produces did:peer:2 with 1 VM (x25519)',
          () async {
        final key = await wallet.generateKey(keyType: KeyType.ed25519);
        await peer2Manager.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.keyAgreement});

        final didDocument = await peer2Manager.getDidDocument();

        // print('--- peer:2 ed25519 keyAgreement only ---');
        // print('DID: ${didDocument.id}');
        // print('VMs: ${didDocument.verificationMethod.length}');
        // for (final vm in didDocument.verificationMethod) {
        //   print('  VM: ${vm.id} (type: ${vm.type})');
        // }
        // print('auth: ${didDocument.authentication.map((e) => e.id).toList()}');
        // print('keyAgreement: ${didDocument.keyAgreement.map((e) => e.id).toList()}');
        // print('---');

        expect(didDocument.id, startsWith('did:peer:2'),
            reason: 'peer2 numalgo should produce did:peer:2');
        expect(didDocument.verificationMethod, hasLength(1),
            reason: 'only derived X25519 VM, no ed25519 primary');
        expect(didDocument.keyAgreement, hasLength(1),
            reason: 'derived X25519 should be in keyAgreement');
        expect(didDocument.authentication, isEmpty,
            reason: 'no authentication requested');

        final resolvedDoc = DidPeer.resolve(didDocument.id);
        expect(resolvedDoc.toJson(), didDocument.toJson(),
            reason:
                'single-purpose peer:2 with 1 VM should resolve identically');
      });
    });

    group('did:peer:0 with Ed25519 + keyAgreement derivation', () {
      test(
          'ed25519 with default relationships (incl. keyAgreement) produces did:peer:0',
          () async {
        final key = await wallet.generateKey(keyType: KeyType.ed25519);

        // Default relationships for ed25519 include keyAgreement,
        // which creates a derived X25519 VM. The manager should still
        // collapse this to did:peer:0 (single source key).
        await manager.addVerificationMethod(key.id);

        final didDocument = await manager.getDidDocument();

        // print('--- peer:0 ed25519 default relationships (incl. keyAgreement) ---');
        // print('DID: ${didDocument.id}');
        // print('VMs: ${didDocument.verificationMethod.length}');
        // for (final vm in didDocument.verificationMethod) {
        //   print('  VM: ${vm.id} (type: ${vm.type})');
        // }
        // print('auth: ${didDocument.authentication.map((e) => e.id).toList()}');
        // print('keyAgreement: ${didDocument.keyAgreement.map((e) => e.id).toList()}');
        // print('assertionMethod: ${didDocument.assertionMethod.map((e) => e.id).toList()}');
        // print('capabilityInvocation: ${didDocument.capabilityInvocation.map((e) => e.id).toList()}');
        // print('capabilityDelegation: ${didDocument.capabilityDelegation.map((e) => e.id).toList()}');
        // print('---');

        expect(didDocument.id, startsWith('did:peer:0'),
            reason:
                'ed25519 + derived X25519 should collapse to did:peer:0 (single source key)');
        expect(didDocument.verificationMethod, hasLength(2),
            reason:
                'ed25519 did:peer:0 resolves to 2 VMs: ed25519 + derived X25519');
        expect(didDocument.authentication, hasLength(1),
            reason: 'ed25519 key should be in authentication');
        expect(didDocument.assertionMethod, hasLength(1),
            reason: 'ed25519 key should be in assertionMethod');
        expect(didDocument.keyAgreement, hasLength(1),
            reason: 'derived X25519 key should be in keyAgreement');
        expect(didDocument.capabilityInvocation, hasLength(1),
            reason: 'ed25519 key should be in capabilityInvocation');
        expect(didDocument.capabilityDelegation, hasLength(1),
            reason: 'ed25519 key should be in capabilityDelegation');

        final resolvedDoc = DidPeer.resolve(didDocument.id);
        expect(resolvedDoc.toJson(), didDocument.toJson(),
            reason: 'did:peer:0 resolution should produce identical document');
      });

      test('ed25519 with only keyAgreement produces did:peer:0 with x25519 key',
          () async {
        final key = await wallet.generateKey(keyType: KeyType.ed25519);

        await manager.addVerificationMethod(key.id,
            relationships: {VerificationRelationship.keyAgreement});

        final didDocument = await manager.getDidDocument();

        // print('--- peer:0 ed25519 keyAgreement only ---');
        // print('DID: ${didDocument.id}');
        // print('VMs: ${didDocument.verificationMethod.length}');
        // for (final vm in didDocument.verificationMethod) {
        //   print('  VM: ${vm.id} (type: ${vm.type})');
        // }
        // print('auth: ${didDocument.authentication.map((e) => e.id).toList()}');
        // print('keyAgreement: ${didDocument.keyAgreement.map((e) => e.id).toList()}');
        // print('---');

        expect(didDocument.id, startsWith('did:peer:0'),
            reason: 'single derived X25519 VM should produce did:peer:0');
        expect(didDocument.verificationMethod, hasLength(1),
            reason: 'only the derived X25519 VM should be present');
        expect(didDocument.keyAgreement, hasLength(1),
            reason: 'X25519 key should be in keyAgreement');
        expect(didDocument.authentication, isEmpty,
            reason: 'no authentication requested, X25519 cannot sign');
      });
    });
  });
}
