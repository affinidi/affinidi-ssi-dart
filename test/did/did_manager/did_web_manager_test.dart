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
  });
}
