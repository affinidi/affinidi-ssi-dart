import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

/// Regression test for did:peer:0 key agreement resolution.
///
/// When a single P-256 key is added to a DidPeerManager with default
/// relationships (including keyAgreement), the resulting DID document
/// must include the key in keyAgreement — matching did:key behavior.
///
/// This was broken in v3.7.0 where the DidPeerManager correctly creates a
/// single VM (producing did:peer:0), but _resolveDidPeer0 did not include
/// EC curves in keyAgreement.
void main() {
  group('did:peer:0 key agreement resolution', () {
    test('P-256 key should appear in keyAgreement', () async {
      final keyStore = InMemoryKeyStore();
      final wallet = PersistentWallet(keyStore);
      final didManager = DidPeerManager(
        wallet: wallet,
        store: InMemoryDidStore(),
      );

      await wallet.generateKey(
        keyId: 'key-1',
        keyType: KeyType.p256,
      );

      await didManager.addVerificationMethod('key-1');
      final didDocument = await didManager.getDidDocument();

      // keyAgreement must not be empty — P-256 supports ECDH
      expect(
        didDocument.keyAgreement,
        isNotEmpty,
        reason:
            'P-256 key in did:peer must appear in keyAgreement (supports ECDH)',
      );
    });

    test('P-384 key should appear in keyAgreement', () async {
      final keyStore = InMemoryKeyStore();
      final wallet = PersistentWallet(keyStore);
      final didManager = DidPeerManager(
        wallet: wallet,
        store: InMemoryDidStore(),
      );

      await wallet.generateKey(
        keyId: 'key-1',
        keyType: KeyType.p384,
      );

      await didManager.addVerificationMethod('key-1');
      final didDocument = await didManager.getDidDocument();

      expect(
        didDocument.keyAgreement,
        isNotEmpty,
        reason:
            'P-384 key in did:peer must appear in keyAgreement (supports ECDH)',
      );
    });

    test('P-521 key should appear in keyAgreement', () async {
      final keyStore = InMemoryKeyStore();
      final wallet = PersistentWallet(keyStore);
      final didManager = DidPeerManager(
        wallet: wallet,
        store: InMemoryDidStore(),
      );

      await wallet.generateKey(
        keyId: 'key-1',
        keyType: KeyType.p521,
      );

      await didManager.addVerificationMethod('key-1');
      final didDocument = await didManager.getDidDocument();

      expect(
        didDocument.keyAgreement,
        isNotEmpty,
        reason:
            'P-521 key in did:peer must appear in keyAgreement (supports ECDH)',
      );
    });

    test('secp256k1 key should NOT appear in keyAgreement', () async {
      final keyStore = InMemoryKeyStore();
      final wallet = PersistentWallet(keyStore);
      final didManager = DidPeerManager(
        wallet: wallet,
        store: InMemoryDidStore(),
      );

      await wallet.generateKey(
        keyId: 'key-1',
        keyType: KeyType.secp256k1,
      );

      await didManager.addVerificationMethod(
        'key-1',
        relationships: {
          VerificationRelationship.authentication,
          VerificationRelationship.assertionMethod,
          VerificationRelationship.capabilityInvocation,
          VerificationRelationship.capabilityDelegation,
        },
      );
      final didDocument = await didManager.getDidDocument();

      // secp256k1 is signing-only per DIDComm spec
      expect(
        didDocument.keyAgreement,
        isEmpty,
        reason: 'secp256k1 key in did:peer should not appear in keyAgreement',
      );
    });

    test('did:peer with P-256 should behave like did:key for key agreement',
        () async {
      // Create did:key with P-256
      final keyKeyStore = InMemoryKeyStore();
      final keyWallet = PersistentWallet(keyKeyStore);
      final didKeyManager = DidKeyManager(
        wallet: keyWallet,
        store: InMemoryDidStore(),
      );

      await keyWallet.generateKey(keyId: 'k1', keyType: KeyType.p256);
      await didKeyManager.addVerificationMethod('k1');
      final didKeyDoc = await didKeyManager.getDidDocument();

      // Create did:peer with P-256
      final peerKeyStore = InMemoryKeyStore();
      final peerWallet = PersistentWallet(peerKeyStore);
      final didPeerManager = DidPeerManager(
        wallet: peerWallet,
        store: InMemoryDidStore(),
      );

      await peerWallet.generateKey(keyId: 'k1', keyType: KeyType.p256);
      await didPeerManager.addVerificationMethod('k1');
      final didPeerDoc = await didPeerManager.getDidDocument();

      // Both should have keyAgreement
      expect(didKeyDoc.keyAgreement, isNotEmpty,
          reason: 'did:key with P-256 has keyAgreement');
      expect(didPeerDoc.keyAgreement, isNotEmpty,
          reason: 'did:peer with P-256 should also have keyAgreement');
    });
  });
}
