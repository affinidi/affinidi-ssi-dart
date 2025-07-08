import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidController Base Functionality', () {
    late Wallet wallet;
    late DidStore store;
    late _TestDidController controller;

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      store = InMemoryDidStore();
      controller = _TestDidController(
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
        await controller.addAuthentication(vmId);
        await controller.addKeyAgreement(vmId);
        await controller.addCapabilityInvocation(vmId);
        await controller.addCapabilityDelegation(vmId);
        await controller.addAssertionMethod(vmId);

        // Verify initial state
        expect(controller.authentication, contains(vmId));
        expect(controller.keyAgreement, contains(vmId));
        expect(controller.capabilityInvocation, contains(vmId));
        expect(controller.capabilityDelegation, contains(vmId));
        expect(controller.assertionMethod, contains(vmId));

        // Act
        await controller.removeAllVerificationMethodReferences(vmId);

        // Assert
        expect(controller.authentication, isNot(contains(vmId)));
        expect(controller.keyAgreement, isNot(contains(vmId)));
        expect(controller.capabilityInvocation, isNot(contains(vmId)));
        expect(controller.capabilityDelegation, isNot(contains(vmId)));
        expect(controller.assertionMethod, isNot(contains(vmId)));
      });

      test('should throw error with empty verification method ID', () async {
        // Act & Assert
        expect(
          () => controller.removeAllVerificationMethodReferences(''),
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

/// Test implementation of DidController for testing base functionality
class _TestDidController extends DidController {
  _TestDidController({
    required super.store,
    required super.wallet,
  });

  @override
  Future<DidDocument> getDidDocument() async {
    // For testing base functionality, we don't need a real document
    // We'll use a peer controller to generate a basic document
    final peerController = DidPeerController(store: store, wallet: wallet);

    // Add a basic key if none exists
    if (authentication.isEmpty &&
        keyAgreement.isEmpty &&
        assertionMethod.isEmpty &&
        capabilityInvocation.isEmpty &&
        capabilityDelegation.isEmpty) {
      final key = await wallet.generateKey(keyId: 'temp-test-key');
      await peerController.addVerificationMethod(key.id,
          relationships: {VerificationRelationship.authentication});
    }

    return peerController.getDidDocument();
  }

  @override
  Future<String> buildVerificationMethodId(PublicKey publicKey,
      {PublicKey? didSourceKey}) async {
    return 'test-vm-${publicKey.id}';
  }
}
