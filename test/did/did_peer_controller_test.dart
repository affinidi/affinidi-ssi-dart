import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidPeerController', () {
    late InMemoryDidStore didStore;
    late PersistentWallet wallet;
    late DidPeerController didPeerController;

    setUp(() {
      didStore = InMemoryDidStore();
      wallet = PersistentWallet(InMemoryKeyStore());
      didPeerController = DidPeerController(store: didStore, wallet: wallet);
    });

    test('throws exception when no keys are added', () {
      expect(
        () => didPeerController.getDidDocument(),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          'At least one key must be added before creating did:peer document',
        )),
      );
    });

    test(
        'generates a valid did:peer:2 document with auth, agreement, and service',
        () async {
      // Generate key
      final key = await wallet.generateKey(keyType: KeyType.ed25519);

      // Add verification method for both auth and key agreement
      await didPeerController.addVerificationMethod(key.id,
          relationships: {
            VerificationRelationship.authentication,
            VerificationRelationship.keyAgreement
          });

      // Add service endpoint
      final serviceEndpoint = ServiceEndpoint(
        id: '#service-1',
        type: 'DIDCommMessaging',
        serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
      );
      await didPeerController.addServiceEndpoint(serviceEndpoint);

      // Get DID Document
      final didDocument = await didPeerController.getDidDocument();

      // Verify DID
      expect(didDocument.id, startsWith('did:peer:2'));

      // Verify verification methods
      expect(didDocument.verificationMethod, hasLength(2));
      expect(didDocument.verificationMethod[0].id, '#key-1');
      expect(didDocument.verificationMethod[0].type, 'Multikey');
      expect(didDocument.verificationMethod[1].id, '#key-2');
      expect(didDocument.verificationMethod[1].type, 'Multikey');

      // Verify verification relationships
      expect(
          didDocument.authentication
              .map((e) => (e as VerificationMethodRef).reference),
          ['#key-1']);
      expect(
          didDocument.keyAgreement
              .map((e) => (e as VerificationMethodRef).reference),
          ['#key-2']);

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

    test('generates a valid did:peer:0 document', () async {
      // Generate key
      final authKey = await wallet.generateKey(keyType: KeyType.ed25519);

      // Add verification method and assign purpose
      await didPeerController.addVerificationMethod(authKey.id,
          relationships: {VerificationRelationship.authentication});

      // Get DID Document
      final didDocument = await didPeerController.getDidDocument();

      // Verify DID
      expect(didDocument.id, startsWith('did:peer:0'));

      // Verify verification method
      expect(didDocument.verificationMethod, hasLength(1));
      expect(didDocument.verificationMethod[0].id, didDocument.id);
      expect(didDocument.verificationMethod[0].type, 'Multikey');

      // Verify verification relationships from generator
      expect(
          didDocument.authentication
              .map((e) => (e as VerificationMethodRef).reference),
          [didDocument.id]);
      expect(
          didDocument.assertionMethod
              .map((e) => (e as VerificationMethodRef).reference),
          [didDocument.id]);
      expect(
          didDocument.capabilityInvocation
              .map((e) => (e as VerificationMethodRef).reference),
          [didDocument.id]);
      expect(
          didDocument.capabilityDelegation
              .map((e) => (e as VerificationMethodRef).reference),
          [didDocument.id]);
      expect(didDocument.keyAgreement, isEmpty);

      // Verify resolution
      final resolvedDoc = DidPeer.resolve(didDocument.id);

      // The resolved document for did:peer:0 will have an additional keyAgreement
      // derived from the authentication key.
      expect(resolvedDoc.id, didDocument.id);
      expect(
          resolvedDoc.authentication
              .map((e) => (e as VerificationMethodRef).reference),
          [didDocument.id]);
      expect(resolvedDoc.keyAgreement, isNotNull);
      expect(resolvedDoc.keyAgreement, hasLength(1));
      expect(resolvedDoc.verificationMethod, hasLength(2));
    });

    test(
        'generates a did:peer:2 document when a service is added, even with one auth key',
        () async {
      // Generate key
      final authKey = await wallet.generateKey(keyType: KeyType.ed25519);

      // Add verification method and assign purpose
      await didPeerController.addVerificationMethod(authKey.id,
          relationships: {VerificationRelationship.authentication});

      // Add service endpoint
      final serviceEndpoint = ServiceEndpoint(
        id: '#service-1',
        type: 'DIDCommMessaging',
        serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
      );
      await didPeerController.addServiceEndpoint(serviceEndpoint);

      // Get DID Document
      final didDocument = await didPeerController.getDidDocument();

      // Verify DID is did:peer:2 because a service was added
      expect(didDocument.id, startsWith('did:peer:2'));

      // Verify resolution
      final resolvedDoc = DidPeer.resolve(didDocument.id);
      expect(resolvedDoc.toJson(), didDocument.toJson());
    });
  });
}
