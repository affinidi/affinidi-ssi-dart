import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidWebManager', () {
    late Wallet wallet;
    late DidStore store;
    late DidWebManager manager;
    final testDomain = Uri.parse('https://example.com');

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      store = InMemoryDidStore();
      manager = DidWebManager(
        store: store,
        wallet: wallet,
        domain: testDomain,
      );
      await manager.init();
    });

    group('addVerificationMethod', () {
      test('should add single key with default relationships', () async {
        final key =
            await wallet.generateKey(keyId: 'key-1', keyType: KeyType.ed25519);

        final result = await manager.addVerificationMethod(key.id);

        expect(result.verificationMethodId, isNotEmpty);
        // ed25519 default relationships include authentication, keyAgreement, etc.
        expect(result.relationships,
            containsPair(VerificationRelationship.authentication, anything));
      });

      test('should add multiple keys with explicit relationships', () async {
        final key1 =
            await wallet.generateKey(keyId: 'key-1', keyType: KeyType.ed25519);
        final key2 =
            await wallet.generateKey(keyId: 'key-2', keyType: KeyType.ed25519);

        final res1 = await manager.addVerificationMethod(
          key1.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.assertionMethod,
          },
        );

        final res2 = await manager.addVerificationMethod(
          key2.id,
          relationships: {
            VerificationRelationship.keyAgreement,
          },
        );

        expect(res1.verificationMethodId, isNotEmpty);
        expect(res2.verificationMethodId, isNotEmpty);
        expect(res1.verificationMethodId, isNot(res2.verificationMethodId));

        expect(res1.relationships,
            containsPair(VerificationRelationship.authentication, anything));
        expect(res1.relationships,
            containsPair(VerificationRelationship.assertionMethod, anything));
        expect(res2.relationships,
            containsPair(VerificationRelationship.keyAgreement, anything));
      });

      test('should add key with empty relationships', () async {
        final key =
            await wallet.generateKey(keyId: 'key-1', keyType: KeyType.p256);

        final result =
            await manager.addVerificationMethod(key.id, relationships: {});

        expect(result.verificationMethodId, isNotEmpty);
        expect(result.relationships, isEmpty);
      });

      test('should maintain sequential key IDs', () async {
        final key1 =
            await wallet.generateKey(keyId: 'k1', keyType: KeyType.p256);
        final key2 =
            await wallet.generateKey(keyId: 'k2', keyType: KeyType.p256);
        final key3 =
            await wallet.generateKey(keyId: 'k3', keyType: KeyType.p256);

        final res1 =
            await manager.addVerificationMethod(key1.id, relationships: {});
        final res2 =
            await manager.addVerificationMethod(key2.id, relationships: {});
        final res3 =
            await manager.addVerificationMethod(key3.id, relationships: {});

        expect(res1.verificationMethodId, 'did:web:example.com#key-1');
        expect(res2.verificationMethodId, 'did:web:example.com#key-2');
        expect(res3.verificationMethodId, 'did:web:example.com#key-3');
      });

      test('should support secp256k1 keys', () async {
        final key = await wallet.generateKey(
            keyId: 'secp-key', keyType: KeyType.secp256k1);

        final result = await manager.addVerificationMethod(
          key.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.assertionMethod,
          },
        );

        expect(result.verificationMethodId, isNotEmpty);
        expect(result.relationships,
            containsPair(VerificationRelationship.authentication, anything));
      });

      test('should derive X25519 key for keyAgreement when using ed25519 key',
          () async {
        final key =
            await wallet.generateKey(keyId: 'ed-key', keyType: KeyType.ed25519);

        final result = await manager.addVerificationMethod(
          key.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.keyAgreement,
          },
        );

        // Should have two different VM IDs: one for auth (ed25519) and one for keyAgreement (x25519)
        expect(result.relationships.length, 2);
        final authVmId =
            result.relationships[VerificationRelationship.authentication];
        final kaVmId =
            result.relationships[VerificationRelationship.keyAgreement];
        expect(authVmId, isNotNull);
        expect(kaVmId, isNotNull);
        expect(authVmId, isNot(kaVmId));
      });
    });

    group('getDidDocument', () {
      test('should throw when no keys are added', () async {
        await expectLater(
          manager.getDidDocument(),
          throwsA(isA<SsiException>()),
        );
      });

      test('should generate single-key did:web document', () async {
        final key =
            await wallet.generateKey(keyId: 'key-1', keyType: KeyType.ed25519);

        await manager.addVerificationMethod(key.id);

        final doc = await manager.getDidDocument();

        expect(doc.id, 'did:web:example.com');
        expect(doc.verificationMethod, isNotEmpty);
        expect(doc.authentication, isNotEmpty);
      });

      test(
          'should generate multi-key did:web document with authentication and keyAgreement',
          () async {
        final key1 =
            await wallet.generateKey(keyId: 'key-1', keyType: KeyType.ed25519);
        final key2 =
            await wallet.generateKey(keyId: 'key-2', keyType: KeyType.ed25519);

        await manager.addVerificationMethod(
          key1.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.assertionMethod,
          },
        );

        await manager.addVerificationMethod(
          key2.id,
          relationships: {
            VerificationRelationship.keyAgreement,
          },
        );

        final doc = await manager.getDidDocument();

        expect(doc.id, 'did:web:example.com');
        // Should have at least 2 VMs (auth/assertion + keyAgreement)
        expect(doc.verificationMethod.length, greaterThanOrEqualTo(2));
        expect(doc.authentication, isNotEmpty);
        expect(doc.assertionMethod, isNotEmpty);
        expect(doc.keyAgreement, isNotEmpty);
      });

      test('should include service endpoints in document', () async {
        final key =
            await wallet.generateKey(keyId: 'key-1', keyType: KeyType.ed25519);

        await manager.addVerificationMethod(key.id);
        await manager.addServiceEndpoint(ServiceEndpoint(
          id: '#service-1',
          type: const StringServiceType('DIDCommMessaging'),
          serviceEndpoint: const StringEndpoint('https://example.com/didcomm'),
        ));

        final doc = await manager.getDidDocument();

        expect(doc.service, isNotEmpty);
        expect(doc.service.first.id, '#service-1');
      });

      test(
          'should generate valid DID document with all five relationship types',
          () async {
        final key = await wallet.generateKey(
            keyId: 'all-purpose', keyType: KeyType.ed25519);

        await manager.addVerificationMethod(
          key.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.assertionMethod,
            VerificationRelationship.keyAgreement,
            VerificationRelationship.capabilityInvocation,
            VerificationRelationship.capabilityDelegation,
          },
        );

        final doc = await manager.getDidDocument();

        expect(doc.id, 'did:web:example.com');
        expect(doc.authentication, isNotEmpty);
        expect(doc.assertionMethod, isNotEmpty);
        expect(doc.keyAgreement, isNotEmpty);
        expect(doc.capabilityInvocation, isNotEmpty);
        expect(doc.capabilityDelegation, isNotEmpty);
      });
    });

    group('did property', () {
      test('should return correct did:web DID', () {
        expect(manager.did, 'did:web:example.com');
      });

      test('should handle domain with port', () async {
        final domainWithPort = Uri.parse('https://example.com:3000');
        final portManager = DidWebManager(
          store: InMemoryDidStore(),
          wallet: wallet,
          domain: domainWithPort,
        );
        await portManager.init();

        expect(portManager.did, 'did:web:example.com%3A3000');
      });

      test('should handle domain with path', () async {
        final domainWithPath = Uri.parse('https://example.com/user/alice');
        final pathManager = DidWebManager(
          store: InMemoryDidStore(),
          wallet: wallet,
          domain: domainWithPath,
        );
        await pathManager.init();

        expect(pathManager.did, 'did:web:example.com:user:alice');
      });
    });

    group('Signing and verification', () {
      test('should sign and verify with authentication key', () async {
        final key = await wallet.generateKey(
            keyId: 'sign-key', keyType: KeyType.ed25519);

        await manager.addVerificationMethod(
          key.id,
          relationships: {
            VerificationRelationship.authentication,
          },
        );

        final doc = await manager.getDidDocument();
        final authVmId = doc.authentication.first.id;

        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final signature = await manager.sign(data, authVmId);
        final verified = await manager.verify(data, signature, authVmId);

        expect(verified, isTrue);
      });

      test('should get DID signer', () async {
        final key = await wallet.generateKey(
            keyId: 'signer-key', keyType: KeyType.ed25519);

        await manager.addVerificationMethod(
          key.id,
          relationships: {
            VerificationRelationship.authentication,
          },
        );

        final doc = await manager.getDidDocument();
        final authVmId = doc.authentication.first.id;

        final signer = await manager.getSigner(authVmId);

        expect(signer.did, 'did:web:example.com');
        expect(signer.didKeyId, contains('did:web:example.com'));
      });
    });

    group('Backward compatibility', () {
      test(
          'single key with no explicit relationships behaves like former DidKeyManager usage',
          () async {
        final key = await wallet.generateKey(
            keyId: 'compat-key', keyType: KeyType.ed25519);

        // No explicit relationships - defaults are applied by base class
        final result = await manager.addVerificationMethod(key.id);

        expect(result.verificationMethodId, isNotEmpty);
        // Default for ed25519 includes authentication, keyAgreement, etc.
        expect(result.relationships, isNotEmpty);

        final doc = await manager.getDidDocument();
        expect(doc.id, 'did:web:example.com');
        expect(doc.verificationMethod, isNotEmpty);
        expect(doc.authentication, isNotEmpty);
      });
    });

    group('Key retrieval', () {
      test('should retrieve DID key pair', () async {
        final key = await wallet.generateKey(
            keyId: 'retrieve-key', keyType: KeyType.ed25519);

        final result = await manager.addVerificationMethod(
          key.id,
          relationships: {VerificationRelationship.authentication},
        );

        final didKeyPair = await manager.getKey(result.verificationMethodId);

        expect(didKeyPair.keyPair.id, key.id);
        expect(didKeyPair.verificationMethodId, result.verificationMethodId);
        expect(didKeyPair.didDocument, isNotNull);
        expect(didKeyPair.didDocument!.id, 'did:web:example.com');
      });
    });

    group('Mixed key types - DID document structure', () {
      test(
          'should produce correct DID document with ed25519 (auth), p256 (keyAgreement), secp256k1 (assertion)',
          () async {
        // --- Arrange: generate 3 keys of different types ---
        final authKey = await wallet.generateKey(
            keyId: 'auth-ed25519', keyType: KeyType.ed25519);
        final kaKey =
            await wallet.generateKey(keyId: 'ka-p256', keyType: KeyType.p256);
        final assertKey = await wallet.generateKey(
            keyId: 'assert-secp256k1', keyType: KeyType.secp256k1);

        // --- Act: add each key with its dedicated relationship ---
        final authResult = await manager.addVerificationMethod(
          authKey.id,
          relationships: {VerificationRelationship.authentication},
        );
        final kaResult = await manager.addVerificationMethod(
          kaKey.id,
          relationships: {VerificationRelationship.keyAgreement},
        );
        final assertResult = await manager.addVerificationMethod(
          assertKey.id,
          relationships: {VerificationRelationship.assertionMethod},
        );

        final doc = await manager.getDidDocument();

        // --- Assert: top-level DID ---
        expect(doc.id, 'did:web:example.com');

        // --- Assert: verificationMethod array has exactly 3 entries ---
        expect(doc.verificationMethod.length, 3);

        // --- Assert: each VM has correct structure ---
        // VM 1: ed25519 authentication key
        final authVm = doc.verificationMethod[0];
        expect(authVm.id, authResult.verificationMethodId);
        expect(authVm.id, 'did:web:example.com#key-1');
        expect(authVm.controller, 'did:web:example.com');
        expect(authVm.type, 'Multikey');
        expect(authVm, isA<VerificationMethodMultibase>());
        final authMultibase =
            (authVm as VerificationMethodMultibase).publicKeyMultibase;
        // ed25519 multibase starts with z6Mk
        expect(authMultibase, startsWith('z6Mk'));

        // VM 2: p256 keyAgreement key
        final kaVm = doc.verificationMethod[1];
        expect(kaVm.id, kaResult.verificationMethodId);
        expect(kaVm.id, 'did:web:example.com#key-2');
        expect(kaVm.controller, 'did:web:example.com');
        expect(kaVm.type, 'Multikey');
        expect(kaVm, isA<VerificationMethodMultibase>());
        final kaMultibase =
            (kaVm as VerificationMethodMultibase).publicKeyMultibase;
        // p256 multibase starts with zDn
        expect(kaMultibase, startsWith('zDn'));

        // VM 3: secp256k1 assertionMethod key
        final assertVm = doc.verificationMethod[2];
        expect(assertVm.id, assertResult.verificationMethodId);
        expect(assertVm.id, 'did:web:example.com#key-3');
        expect(assertVm.controller, 'did:web:example.com');
        expect(assertVm.type, 'Multikey');
        expect(assertVm, isA<VerificationMethodMultibase>());
        final assertMultibase =
            (assertVm as VerificationMethodMultibase).publicKeyMultibase;
        // secp256k1 multibase starts with zQ3s
        expect(assertMultibase, startsWith('zQ3s'));

        // --- Assert: authentication references only the ed25519 key ---
        expect(doc.authentication.length, 1);
        expect(doc.authentication.first.id, 'did:web:example.com#key-1');

        // --- Assert: keyAgreement references only the p256 key ---
        expect(doc.keyAgreement.length, 1);
        expect(doc.keyAgreement.first.id, 'did:web:example.com#key-2');

        // --- Assert: assertionMethod references only the secp256k1 key ---
        expect(doc.assertionMethod.length, 1);
        expect(doc.assertionMethod.first.id, 'did:web:example.com#key-3');

        // --- Assert: unused relationship arrays are empty ---
        expect(doc.capabilityInvocation, isEmpty);
        expect(doc.capabilityDelegation, isEmpty);
      });

      test(
          'DID document JSON structure matches expected format with mixed key types',
          () async {
        // Arrange
        final authKey = await wallet.generateKey(
            keyId: 'auth-ed', keyType: KeyType.ed25519);
        final kaKey =
            await wallet.generateKey(keyId: 'ka-p', keyType: KeyType.p256);
        final assertKey = await wallet.generateKey(
            keyId: 'assert-s', keyType: KeyType.secp256k1);

        await manager.addVerificationMethod(
          authKey.id,
          relationships: {VerificationRelationship.authentication},
        );
        await manager.addVerificationMethod(
          kaKey.id,
          relationships: {VerificationRelationship.keyAgreement},
        );
        await manager.addVerificationMethod(
          assertKey.id,
          relationships: {VerificationRelationship.assertionMethod},
        );

        final doc = await manager.getDidDocument();
        final json = doc.toJson();

        // --- Assert: JSON structure ---
        expect(json['id'], 'did:web:example.com');
        expect(json['@context'], contains('https://www.w3.org/ns/did/v1'));
        expect(json['@context'],
            contains('https://w3id.org/security/multikey/v1'));

        // verificationMethod array
        final vms = json['verificationMethod'] as List;
        expect(vms.length, 3);

        // VM 1: ed25519
        expect(vms[0]['id'], 'did:web:example.com#key-1');
        expect(vms[0]['controller'], 'did:web:example.com');
        expect(vms[0]['type'], 'Multikey');
        expect((vms[0]['publicKeyMultibase'] as String), startsWith('z6Mk'));

        // VM 2: p256
        expect(vms[1]['id'], 'did:web:example.com#key-2');
        expect(vms[1]['controller'], 'did:web:example.com');
        expect(vms[1]['type'], 'Multikey');
        expect((vms[1]['publicKeyMultibase'] as String), startsWith('zDn'));

        // VM 3: secp256k1
        expect(vms[2]['id'], 'did:web:example.com#key-3');
        expect(vms[2]['controller'], 'did:web:example.com');
        expect(vms[2]['type'], 'Multikey');
        expect((vms[2]['publicKeyMultibase'] as String), startsWith('zQ3s'));

        // relationship arrays reference the correct VM IDs
        expect(json['authentication'], ['did:web:example.com#key-1']);
        expect(json['keyAgreement'], ['did:web:example.com#key-2']);
        expect(json['assertionMethod'], ['did:web:example.com#key-3']);
      });

      test(
          'should handle ed25519 key used for both authentication and keyAgreement (auto X25519 derivation)',
          () async {
        // When ed25519 is used for keyAgreement, DidWebManager derives an X25519 key
        final edKey = await wallet.generateKey(
            keyId: 'ed-dual', keyType: KeyType.ed25519);

        await manager.addVerificationMethod(
          edKey.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.keyAgreement,
          },
        );

        final doc = await manager.getDidDocument();

        // Should have 2 VMs: one ed25519 (auth) + one derived x25519 (keyAgreement)
        expect(doc.verificationMethod.length, 2);

        // Auth VM: ed25519 → multibase starts with z6Mk
        final authVm = doc.verificationMethod[0];
        expect(authVm.id, 'did:web:example.com#key-1');
        expect((authVm as VerificationMethodMultibase).publicKeyMultibase,
            startsWith('z6Mk'));

        // KeyAgreement VM: derived x25519 → multibase starts with z6LS
        final kaVm = doc.verificationMethod[1];
        expect(kaVm.id, 'did:web:example.com#key-2');
        expect((kaVm as VerificationMethodMultibase).publicKeyMultibase,
            startsWith('z6LS'));

        // Relationship references
        expect(doc.authentication.length, 1);
        expect(doc.authentication.first.id, 'did:web:example.com#key-1');
        expect(doc.keyAgreement.length, 1);
        expect(doc.keyAgreement.first.id, 'did:web:example.com#key-2');
      });

      test('signing works with each key type in a mixed-key document',
          () async {
        final authKey = await wallet.generateKey(
            keyId: 'sign-ed', keyType: KeyType.ed25519);
        final assertKey = await wallet.generateKey(
            keyId: 'sign-secp', keyType: KeyType.secp256k1);

        await manager.addVerificationMethod(
          authKey.id,
          relationships: {VerificationRelationship.authentication},
        );
        await manager.addVerificationMethod(
          assertKey.id,
          relationships: {VerificationRelationship.assertionMethod},
        );

        final doc = await manager.getDidDocument();
        final data = Uint8List.fromList([10, 20, 30, 40, 50]);

        // Sign + verify with ed25519 authentication key
        final authVmId = doc.authentication.first.id;
        final authSig = await manager.sign(data, authVmId);
        expect(await manager.verify(data, authSig, authVmId), isTrue);

        // Sign + verify with secp256k1 assertion key
        final assertVmId = doc.assertionMethod.first.id;
        final assertSig = await manager.sign(data, assertVmId);
        expect(await manager.verify(data, assertSig, assertVmId), isTrue);
      });
    });

    // ================================================================
    // Same key type — multiple keys sharing the same relationships
    // ================================================================
    group('Same key type - multiple keys with shared relationships', () {
      test('2 ed25519 keys: both with authentication + assertionMethod',
          () async {
        final key1 =
            await wallet.generateKey(keyId: 'ed-1', keyType: KeyType.ed25519);
        final key2 =
            await wallet.generateKey(keyId: 'ed-2', keyType: KeyType.ed25519);

        await manager.addVerificationMethod(
          key1.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.assertionMethod,
          },
        );
        await manager.addVerificationMethod(
          key2.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.assertionMethod,
          },
        );

        final doc = await manager.getDidDocument();
        final json = doc.toJson();

        expect(doc.id, 'did:web:example.com');

        // 2 VMs — one per key (not 4)
        expect(doc.verificationMethod.length, 2);

        for (var i = 0; i < 2; i++) {
          final vm = doc.verificationMethod[i] as VerificationMethodMultibase;
          expect(vm.id, 'did:web:example.com#key-${i + 1}');
          expect(vm.controller, 'did:web:example.com');
          expect(vm.type, 'Multikey');
          expect(vm.publicKeyMultibase, startsWith('z6Mk')); // ed25519
        }

        // key1 and key2 are different keys
        final vm1mb = (doc.verificationMethod[0] as VerificationMethodMultibase)
            .publicKeyMultibase;
        final vm2mb = (doc.verificationMethod[1] as VerificationMethodMultibase)
            .publicKeyMultibase;
        expect(vm1mb, isNot(vm2mb));

        // authentication: both keys
        expect(doc.authentication.length, 2);
        expect(json['authentication'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
        ]);

        // assertionMethod: same VMs (one-to-one reuse)
        expect(doc.assertionMethod.length, 2);
        expect(json['assertionMethod'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
        ]);

        expect(doc.keyAgreement, isEmpty);
        expect(doc.capabilityInvocation, isEmpty);
        expect(doc.capabilityDelegation, isEmpty);
      });

      test('3 p256 keys: all with authentication + keyAgreement', () async {
        final key1 =
            await wallet.generateKey(keyId: 'p-1', keyType: KeyType.p256);
        final key2 =
            await wallet.generateKey(keyId: 'p-2', keyType: KeyType.p256);
        final key3 =
            await wallet.generateKey(keyId: 'p-3', keyType: KeyType.p256);

        for (final key in [key1, key2, key3]) {
          await manager.addVerificationMethod(
            key.id,
            relationships: {
              VerificationRelationship.authentication,
              VerificationRelationship.keyAgreement,
            },
          );
        }

        final doc = await manager.getDidDocument();
        final json = doc.toJson();

        expect(doc.id, 'did:web:example.com');

        // 3 VMs — one per key (not 6)
        expect(doc.verificationMethod.length, 3);

        for (var i = 0; i < 3; i++) {
          final vm = doc.verificationMethod[i] as VerificationMethodMultibase;
          expect(vm.id, 'did:web:example.com#key-${i + 1}');
          expect(vm.controller, 'did:web:example.com');
          expect(vm.type, 'Multikey');
          expect(vm.publicKeyMultibase, startsWith('zDn')); // p256
        }

        // Different wallet keys have different public material
        final mb1 = (doc.verificationMethod[0] as VerificationMethodMultibase)
            .publicKeyMultibase;
        final mb2 = (doc.verificationMethod[1] as VerificationMethodMultibase)
            .publicKeyMultibase;
        final mb3 = (doc.verificationMethod[2] as VerificationMethodMultibase)
            .publicKeyMultibase;
        expect({mb1, mb2, mb3}.length, 3); // all distinct

        // authentication: all 3 keys
        expect(json['authentication'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
          'did:web:example.com#key-3',
        ]);

        // keyAgreement: same 3 VMs (p256 does not require X25519 derivation)
        expect(json['keyAgreement'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
          'did:web:example.com#key-3',
        ]);

        expect(doc.assertionMethod, isEmpty);
        expect(doc.capabilityInvocation, isEmpty);
        expect(doc.capabilityDelegation, isEmpty);
      });

      test('2 secp256k1 keys: both with assertionMethod + capabilityInvocation',
          () async {
        final key1 = await wallet.generateKey(
            keyId: 'secp-1', keyType: KeyType.secp256k1);
        final key2 = await wallet.generateKey(
            keyId: 'secp-2', keyType: KeyType.secp256k1);

        await manager.addVerificationMethod(
          key1.id,
          relationships: {
            VerificationRelationship.assertionMethod,
            VerificationRelationship.capabilityInvocation,
          },
        );
        await manager.addVerificationMethod(
          key2.id,
          relationships: {
            VerificationRelationship.assertionMethod,
            VerificationRelationship.capabilityInvocation,
          },
        );

        final doc = await manager.getDidDocument();
        final json = doc.toJson();

        // 2 VMs — one per key (not 4)
        expect(doc.verificationMethod.length, 2);

        for (var i = 0; i < 2; i++) {
          final vm = doc.verificationMethod[i] as VerificationMethodMultibase;
          expect(vm.id, 'did:web:example.com#key-${i + 1}');
          expect(vm.type, 'Multikey');
          expect(vm.publicKeyMultibase, startsWith('zQ3s')); // secp256k1
        }

        final vm1mb = (doc.verificationMethod[0] as VerificationMethodMultibase)
            .publicKeyMultibase;
        final vm2mb = (doc.verificationMethod[1] as VerificationMethodMultibase)
            .publicKeyMultibase;
        expect(vm1mb, isNot(vm2mb));

        // capabilityInvocation: #key-1, #key-2
        expect(doc.capabilityInvocation.length, 2);
        expect(json['capabilityInvocation'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
        ]);

        // assertionMethod: same VMs #key-1, #key-2
        expect(doc.assertionMethod.length, 2);
        expect(json['assertionMethod'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
        ]);

        expect(doc.authentication, isEmpty);
        expect(doc.keyAgreement, isEmpty);
        expect(doc.capabilityDelegation, isEmpty);
      });

      test(
          '3 secp256k1 keys: all with authentication + assertionMethod + keyAgreement',
          () async {
        final key1 = await wallet.generateKey(
            keyId: 'secp-a', keyType: KeyType.secp256k1);
        final key2 = await wallet.generateKey(
            keyId: 'secp-b', keyType: KeyType.secp256k1);
        final key3 = await wallet.generateKey(
            keyId: 'secp-c', keyType: KeyType.secp256k1);

        final allRelationships = {
          VerificationRelationship.authentication,
          VerificationRelationship.assertionMethod,
          VerificationRelationship.keyAgreement,
        };

        for (final key in [key1, key2, key3]) {
          await manager.addVerificationMethod(
            key.id,
            relationships: allRelationships,
          );
        }

        final doc = await manager.getDidDocument();
        final json = doc.toJson();

        // 3 VMs — one per key (not 9)
        expect(doc.verificationMethod.length, 3);

        for (var i = 0; i < 3; i++) {
          final vm = doc.verificationMethod[i] as VerificationMethodMultibase;
          expect(vm.id, 'did:web:example.com#key-${i + 1}');
          expect(vm.type, 'Multikey');
          expect(vm.publicKeyMultibase, startsWith('zQ3s'));
        }

        expect(json['authentication'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
          'did:web:example.com#key-3',
        ]);
        expect(json['keyAgreement'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
          'did:web:example.com#key-3',
        ]);
        expect(json['assertionMethod'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
          'did:web:example.com#key-3',
        ]);

        expect(doc.capabilityInvocation, isEmpty);
        expect(doc.capabilityDelegation, isEmpty);
      });
    });

    // ================================================================
    // Different key types — multiple keys sharing the same relationships
    // ================================================================
    group('Different key types - multiple keys with shared relationships', () {
      test(
          '2 keys (ed25519 + p256): both with authentication + assertionMethod',
          () async {
        final edKey = await wallet.generateKey(
            keyId: 'ed-auth', keyType: KeyType.ed25519);
        final p256Key =
            await wallet.generateKey(keyId: 'p256-auth', keyType: KeyType.p256);

        await manager.addVerificationMethod(
          edKey.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.assertionMethod,
          },
        );
        await manager.addVerificationMethod(
          p256Key.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.assertionMethod,
          },
        );

        final doc = await manager.getDidDocument();
        final json = doc.toJson();

        expect(doc.id, 'did:web:example.com');

        // 2 VMs — one per key (not 4)
        expect(doc.verificationMethod.length, 2);

        final vm1 = doc.verificationMethod[0] as VerificationMethodMultibase;
        expect(vm1.id, 'did:web:example.com#key-1');
        expect(vm1.publicKeyMultibase, startsWith('z6Mk')); // ed25519

        final vm2 = doc.verificationMethod[1] as VerificationMethodMultibase;
        expect(vm2.id, 'did:web:example.com#key-2');
        expect(vm2.publicKeyMultibase, startsWith('zDn')); // p256

        // authentication: #key-1 (ed25519) + #key-2 (p256)
        expect(json['authentication'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
        ]);
        // assertionMethod: same VMs
        expect(json['assertionMethod'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
        ]);

        expect(doc.keyAgreement, isEmpty);
        expect(doc.capabilityInvocation, isEmpty);
        expect(doc.capabilityDelegation, isEmpty);
      });

      test('2 keys (ed25519 + secp256k1): both with keyAgreement', () async {
        // ed25519 used for keyAgreement → derives X25519 automatically
        // secp256k1 used for keyAgreement → stays secp256k1
        final edKey =
            await wallet.generateKey(keyId: 'ed-ka', keyType: KeyType.ed25519);
        final secpKey = await wallet.generateKey(
            keyId: 'secp-ka', keyType: KeyType.secp256k1);

        await manager.addVerificationMethod(
          edKey.id,
          relationships: {VerificationRelationship.keyAgreement},
        );
        await manager.addVerificationMethod(
          secpKey.id,
          relationships: {VerificationRelationship.keyAgreement},
        );

        final doc = await manager.getDidDocument();
        final json = doc.toJson();

        // --- verificationMethod: 2 VMs ---
        expect(doc.verificationMethod.length, 2);

        // VM 1: derived x25519 from ed25519 (because only keyAgreement was requested)
        final vm1 = doc.verificationMethod[0] as VerificationMethodMultibase;
        expect(vm1.id, 'did:web:example.com#key-1');
        expect(vm1.type, 'Multikey');
        expect(vm1.publicKeyMultibase, startsWith('z6LS')); // x25519

        // VM 2: secp256k1 (used directly for keyAgreement)
        final vm2 = doc.verificationMethod[1] as VerificationMethodMultibase;
        expect(vm2.id, 'did:web:example.com#key-2');
        expect(vm2.type, 'Multikey');
        expect(vm2.publicKeyMultibase, startsWith('zQ3s')); // secp256k1

        // --- keyAgreement: both ---
        expect(doc.keyAgreement.length, 2);
        expect(json['keyAgreement'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
        ]);

        // --- unused ---
        expect(doc.authentication, isEmpty);
        expect(doc.assertionMethod, isEmpty);
        expect(doc.capabilityInvocation, isEmpty);
        expect(doc.capabilityDelegation, isEmpty);
      });

      test(
          '3 keys (ed25519 + p256 + secp256k1): all with authentication + assertionMethod + keyAgreement',
          () async {
        final edKey =
            await wallet.generateKey(keyId: 'ed-all', keyType: KeyType.ed25519);
        final p256Key =
            await wallet.generateKey(keyId: 'p256-all', keyType: KeyType.p256);
        final secpKey = await wallet.generateKey(
            keyId: 'secp-all', keyType: KeyType.secp256k1);

        final allRelationships = {
          VerificationRelationship.authentication,
          VerificationRelationship.assertionMethod,
          VerificationRelationship.keyAgreement,
        };

        await manager.addVerificationMethod(edKey.id,
            relationships: allRelationships);
        await manager.addVerificationMethod(p256Key.id,
            relationships: allRelationships);
        await manager.addVerificationMethod(secpKey.id,
            relationships: allRelationships);

        final doc = await manager.getDidDocument();
        final json = doc.toJson();

        expect(doc.id, 'did:web:example.com');

        // 4 VMs (not 9):
        // #key-1  ed25519   (auth + assertion for ed25519 key)
        // #key-2  x25519    (keyAgreement derived from ed25519 key)
        // #key-3  p256      (auth + keyAgreement + assertion for p256 key)
        // #key-4  secp256k1 (auth + keyAgreement + assertion for secp256k1 key)
        expect(doc.verificationMethod.length, 4);

        final vm1 = doc.verificationMethod[0] as VerificationMethodMultibase;
        expect(vm1.id, 'did:web:example.com#key-1');
        expect(vm1.publicKeyMultibase, startsWith('z6Mk')); // ed25519

        final vm2 = doc.verificationMethod[1] as VerificationMethodMultibase;
        expect(vm2.id, 'did:web:example.com#key-2');
        expect(vm2.publicKeyMultibase, startsWith('z6LS')); // x25519 derived

        final vm3 = doc.verificationMethod[2] as VerificationMethodMultibase;
        expect(vm3.id, 'did:web:example.com#key-3');
        expect(vm3.publicKeyMultibase, startsWith('zDn')); // p256

        final vm4 = doc.verificationMethod[3] as VerificationMethodMultibase;
        expect(vm4.id, 'did:web:example.com#key-4');
        expect(vm4.publicKeyMultibase, startsWith('zQ3s')); // secp256k1

        // authentication: ed25519(#key-1), p256(#key-3), secp256k1(#key-4)
        expect(json['authentication'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-3',
          'did:web:example.com#key-4',
        ]);
        // keyAgreement: x25519(#key-2), p256(#key-3), secp256k1(#key-4)
        expect(json['keyAgreement'], [
          'did:web:example.com#key-2',
          'did:web:example.com#key-3',
          'did:web:example.com#key-4',
        ]);
        // assertionMethod: ed25519(#key-1), p256(#key-3), secp256k1(#key-4)
        expect(json['assertionMethod'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-3',
          'did:web:example.com#key-4',
        ]);

        expect(doc.capabilityInvocation, isEmpty);
        expect(doc.capabilityDelegation, isEmpty);
      });

      test('3 keys (ed25519 + p256 + secp256k1): all with authentication only',
          () async {
        final edKey =
            await wallet.generateKey(keyId: 'ed-a', keyType: KeyType.ed25519);
        final p256Key =
            await wallet.generateKey(keyId: 'p256-a', keyType: KeyType.p256);
        final secpKey = await wallet.generateKey(
            keyId: 'secp-a', keyType: KeyType.secp256k1);

        for (final key in [edKey, p256Key, secpKey]) {
          await manager.addVerificationMethod(
            key.id,
            relationships: {VerificationRelationship.authentication},
          );
        }

        final doc = await manager.getDidDocument();
        final json = doc.toJson();

        // --- verificationMethod: 3 VMs, one per key type ---
        expect(doc.verificationMethod.length, 3);

        // VM 1: ed25519
        final vm1 = doc.verificationMethod[0] as VerificationMethodMultibase;
        expect(vm1.id, 'did:web:example.com#key-1');
        expect(vm1.type, 'Multikey');
        expect(vm1.publicKeyMultibase, startsWith('z6Mk'));

        // VM 2: p256
        final vm2 = doc.verificationMethod[1] as VerificationMethodMultibase;
        expect(vm2.id, 'did:web:example.com#key-2');
        expect(vm2.type, 'Multikey');
        expect(vm2.publicKeyMultibase, startsWith('zDn'));

        // VM 3: secp256k1
        final vm3 = doc.verificationMethod[2] as VerificationMethodMultibase;
        expect(vm3.id, 'did:web:example.com#key-3');
        expect(vm3.type, 'Multikey');
        expect(vm3.publicKeyMultibase, startsWith('zQ3s'));

        // --- authentication: all 3 ---
        expect(doc.authentication.length, 3);
        expect(json['authentication'], [
          'did:web:example.com#key-1',
          'did:web:example.com#key-2',
          'did:web:example.com#key-3',
        ]);

        // --- everything else empty ---
        expect(doc.assertionMethod, isEmpty);
        expect(doc.keyAgreement, isEmpty);
        expect(doc.capabilityInvocation, isEmpty);
        expect(doc.capabilityDelegation, isEmpty);
      });
    });

    // ================================================================
    // One-to-one key → VM mapping tests
    // ================================================================
    group('One-to-one key to VM mapping', () {
      test(
        '1 ed25519 key with {auth, assertion, capInvoke, capDelegate} → 1 VM, all 4 arrays reference it',
        () async {
          final key = await wallet.generateKey(
              keyId: 'ed-4rel', keyType: KeyType.ed25519);
          await manager.addVerificationMethod(
            key.id,
            relationships: {
              VerificationRelationship.authentication,
              VerificationRelationship.assertionMethod,
              VerificationRelationship.capabilityInvocation,
              VerificationRelationship.capabilityDelegation,
            },
          );
          final doc = await manager.getDidDocument();
          expect(doc.verificationMethod.length, 1);
          expect(doc.verificationMethod.first.id, 'did:web:example.com#key-1');
          expect(doc.authentication.first.id, 'did:web:example.com#key-1');
          expect(doc.assertionMethod.first.id, 'did:web:example.com#key-1');
          expect(
              doc.capabilityInvocation.first.id, 'did:web:example.com#key-1');
          expect(
              doc.capabilityDelegation.first.id, 'did:web:example.com#key-1');
          expect(doc.keyAgreement, isEmpty);
        },
      );

      test(
        '1 p256 key with {auth, keyAgreement} → 1 VM, both arrays reference same VM',
        () async {
          final key = await wallet.generateKey(
              keyId: 'p256-2rel', keyType: KeyType.p256);
          await manager.addVerificationMethod(
            key.id,
            relationships: {
              VerificationRelationship.authentication,
              VerificationRelationship.keyAgreement,
            },
          );
          final doc = await manager.getDidDocument();
          expect(doc.verificationMethod.length, 1);
          expect(doc.verificationMethod.first.id, 'did:web:example.com#key-1');
          expect(doc.authentication.first.id, 'did:web:example.com#key-1');
          expect(doc.keyAgreement.first.id, 'did:web:example.com#key-1');
        },
      );

      test(
        'ed25519 key with all 5 relationships → exactly 2 VMs: #key-1 (ed25519) + #key-2 (X25519)',
        () async {
          final key = await wallet.generateKey(
              keyId: 'ed-all5', keyType: KeyType.ed25519);
          final result = await manager.addVerificationMethod(
            key.id,
            relationships: {
              VerificationRelationship.authentication,
              VerificationRelationship.assertionMethod,
              VerificationRelationship.keyAgreement,
              VerificationRelationship.capabilityInvocation,
              VerificationRelationship.capabilityDelegation,
            },
          );

          // Primary VM is the ed25519 one
          expect(result.verificationMethodId, 'did:web:example.com#key-1');
          // keyAgreement maps to the derived X25519 VM
          expect(result.relationships[VerificationRelationship.keyAgreement],
              'did:web:example.com#key-2');
          // All other relationships map to the primary VM
          expect(result.relationships[VerificationRelationship.authentication],
              'did:web:example.com#key-1');
          expect(result.relationships[VerificationRelationship.assertionMethod],
              'did:web:example.com#key-1');
          expect(
              result
                  .relationships[VerificationRelationship.capabilityInvocation],
              'did:web:example.com#key-1');
          expect(
              result
                  .relationships[VerificationRelationship.capabilityDelegation],
              'did:web:example.com#key-1');

          final doc = await manager.getDidDocument();
          expect(doc.verificationMethod.length, 2);

          final vm1 = doc.verificationMethod[0] as VerificationMethodMultibase;
          expect(vm1.id, 'did:web:example.com#key-1');
          expect(vm1.publicKeyMultibase, startsWith('z6Mk')); // ed25519

          final vm2 = doc.verificationMethod[1] as VerificationMethodMultibase;
          expect(vm2.id, 'did:web:example.com#key-2');
          expect(vm2.publicKeyMultibase, startsWith('z6LS')); // x25519

          // non-keyAgreement arrays all reference #key-1
          expect(doc.authentication.first.id, 'did:web:example.com#key-1');
          expect(doc.assertionMethod.first.id, 'did:web:example.com#key-1');
          expect(
              doc.capabilityInvocation.first.id, 'did:web:example.com#key-1');
          expect(
              doc.capabilityDelegation.first.id, 'did:web:example.com#key-1');
          // keyAgreement references the derived X25519
          expect(doc.keyAgreement.first.id, 'did:web:example.com#key-2');
        },
      );

      test(
        'sign+verify still works after one-to-one fix: ed25519 key with auth+keyAgreement',
        () async {
          final key = await wallet.generateKey(
              keyId: 'ed-sign', keyType: KeyType.ed25519);
          final result = await manager.addVerificationMethod(
            key.id,
            relationships: {
              VerificationRelationship.authentication,
              VerificationRelationship.keyAgreement,
            },
          );

          final authVmId =
              result.relationships[VerificationRelationship.authentication]!;
          final data = Uint8List.fromList([1, 2, 3, 4, 5]);
          final sig = await manager.sign(data, authVmId);
          expect(await manager.verify(data, sig, authVmId), isTrue);
        },
      );

      test(
        'ed25519 default relationships (all 5) produce exactly 2 VMs: ed25519 + derived X25519',
        () async {
          final key = await wallet.generateKey(
              keyId: 'ed-default', keyType: KeyType.ed25519);

          // No explicit relationships — defaults applied by base class:
          // {auth, assertion, keyAgreement, capInvoke, capDelegate}
          final result = await manager.addVerificationMethod(key.id);

          // Primary VM is the ed25519 one
          expect(result.verificationMethodId, 'did:web:example.com#key-1');

          // keyAgreement maps to the derived X25519 VM
          expect(result.relationships[VerificationRelationship.keyAgreement],
              'did:web:example.com#key-2');

          // All other relationships map to the primary VM
          for (final rel in [
            VerificationRelationship.authentication,
            VerificationRelationship.assertionMethod,
            VerificationRelationship.capabilityInvocation,
            VerificationRelationship.capabilityDelegation,
          ]) {
            expect(result.relationships[rel], 'did:web:example.com#key-1');
          }

          final doc = await manager.getDidDocument();

          // Exactly 2 VMs: #key-1 (ed25519) + #key-2 (x25519)
          expect(doc.verificationMethod.length, 2);

          final vm1 = doc.verificationMethod[0] as VerificationMethodMultibase;
          expect(vm1.id, 'did:web:example.com#key-1');
          expect(vm1.publicKeyMultibase, startsWith('z6Mk')); // ed25519

          final vm2 = doc.verificationMethod[1] as VerificationMethodMultibase;
          expect(vm2.id, 'did:web:example.com#key-2');
          expect(vm2.publicKeyMultibase, startsWith('z6LS')); // x25519

          // All non-keyAgreement arrays reference #key-1
          final json = doc.toJson();
          expect(json['authentication'], ['did:web:example.com#key-1']);
          expect(json['assertionMethod'], ['did:web:example.com#key-1']);
          expect(json['capabilityInvocation'], ['did:web:example.com#key-1']);
          expect(json['capabilityDelegation'], ['did:web:example.com#key-1']);
          // keyAgreement references the derived X25519
          expect(json['keyAgreement'], ['did:web:example.com#key-2']);
        },
      );
    });
  });
}
