import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidManager Base Functionality', () {
    late Wallet wallet;
    late DidStore store;
    late _TestDidManager manager;

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      store = InMemoryDidStore();
      manager = _TestDidManager(
        store: store,
        wallet: wallet,
      );
    });

    group('removeAllVerificationMethodReferences', () {
      test('should remove VM from all relationships', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'remove-all-test');
        const vmId = 'test-vm-remove-all';
        await store.setMapping(vmId, keyPair.id);

        // Add to multiple relationships
        await manager.addAuthentication(vmId);
        await manager.addKeyAgreement(vmId);
        await manager.addCapabilityInvocation(vmId);
        await manager.addCapabilityDelegation(vmId);
        await manager.addAssertionMethod(vmId);

        // Verify initial state
        expect(manager.authentication, contains(vmId));
        expect(manager.keyAgreement, contains(vmId));
        expect(manager.capabilityInvocation, contains(vmId));
        expect(manager.capabilityDelegation, contains(vmId));
        expect(manager.assertionMethod, contains(vmId));

        // Act
        await manager.removeAllVerificationMethodReferences(vmId);

        // Assert
        expect(manager.authentication, isNot(contains(vmId)));
        expect(manager.keyAgreement, isNot(contains(vmId)));
        expect(manager.capabilityInvocation, isNot(contains(vmId)));
        expect(manager.capabilityDelegation, isNot(contains(vmId)));
        expect(manager.assertionMethod, isNot(contains(vmId)));
      });

      test('should throw error with empty verification method ID', () async {
        // Act & Assert
        expect(
          () => manager.removeAllVerificationMethodReferences(''),
          throwsA(
            isA<SsiException>().having(
              (e) => e.message,
              'message',
              'Verification method ID cannot be empty',
            ),
          ),
        );
      });
    });
  });
}

/// Test implementation of DidManager for testing base functionality
class _TestDidManager extends DidManager {
  _TestDidManager({
    required super.store,
    required super.wallet,
  });

  @override
  Future<DidDocument> getDidDocument() async {
    // For testing base functionality, we don't need a real document
    // We'll use a peer manager to generate a basic document
    final peerManager = DidPeerManager(store: store, wallet: wallet);

    // Add a basic key if none exists
    if (authentication.isEmpty &&
        keyAgreement.isEmpty &&
        assertionMethod.isEmpty &&
        capabilityInvocation.isEmpty &&
        capabilityDelegation.isEmpty) {
      final key = await wallet.generateKey(keyId: 'temp-test-key');
      await peerManager.addVerificationMethod(key.id,
          relationships: {VerificationRelationship.authentication});
    }

    return peerManager.getDidDocument();
  }

  @override
  Future<String> buildVerificationMethodId(PublicKey publicKey) async {
    return 'test-vm-${publicKey.id}';
  }
}
