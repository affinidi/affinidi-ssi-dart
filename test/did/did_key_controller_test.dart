import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidKeyController', () {
    late InMemoryDidStore didStore;
    late PersistentWallet wallet;
    late DidKeyController didKeyController;

    setUp(() {
      didStore = InMemoryDidStore();
      wallet = PersistentWallet(InMemoryKeyStore());
      didKeyController = DidKeyController(store: didStore, wallet: wallet);
    });

    test('throws exception when no key is added', () {
      expect(
        () => didKeyController.getDidDocument(),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          'DidKey expects a single key.',
        )),
      );
    });

    test('generates a valid did:key document', () async {
      // Generate key
      final key = await wallet.generateKey(keyType: KeyType.ed25519);

      // Add verification method
      final result = await didKeyController.addVerificationMethod(key.id);
      final vmId = result.verificationMethodId;

      // Get DID Document
      final didDocument = await didKeyController.getDidDocument();

      // Verify DID
      expect(didDocument.id, startsWith('did:key:z6Mk'));
      expect(vmId, startsWith('did:key:z6Mk'));
      expect(vmId, endsWith(didDocument.id.substring(8)));

      // Verify verification methods
      // Expect 2: one for signing, one derived for key agreement
      expect(didDocument.verificationMethod, hasLength(2));

      final signVm = didDocument.verificationMethod
          .firstWhere((vm) => vm.type == 'Ed25519VerificationKey2020');
      final agreeVm = didDocument.verificationMethod
          .firstWhere((vm) => vm.type == 'X25519KeyAgreementKey2020');

      expect(signVm.id, vmId);
      expect(agreeVm.id, isNot(vmId));
      expect(agreeVm.id, startsWith(didDocument.id));

      // Verify verification relationships
      expect(
          didDocument.authentication
              .map((e) => (e as VerificationMethodRef).reference),
          [vmId]);
      expect(
          didDocument.assertionMethod
              .map((e) => (e as VerificationMethodRef).reference),
          [vmId]);
      expect(
          didDocument.capabilityInvocation
              .map((e) => (e as VerificationMethodRef).reference),
          [vmId]);
      expect(
          didDocument.capabilityDelegation
              .map((e) => (e as VerificationMethodRef).reference),
          [vmId]);

      expect(didDocument.keyAgreement, hasLength(1));
      expect(
          didDocument.keyAgreement
              .map((e) => (e as VerificationMethodRef).reference),
          [agreeVm.id]);
    });

    test('throws exception when adding a second key', () async {
      // Add first key
      final key1 = await wallet.generateKey(keyType: KeyType.ed25519);
      await didKeyController.addVerificationMethod(key1.id);

      // Attempt to add second key
      final key2 = await wallet.generateKey(keyType: KeyType.ed25519);
      expect(
        () => didKeyController.addVerificationMethod(key2.id),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          'did:key method supports only one key.',
        )),
      );
    });

    test('throws exception when adding a service endpoint', () {
      final serviceEndpoint = ServiceEndpoint(
        id: '#service-1',
        type: 'TestService',
        serviceEndpoint: const StringEndpoint('https://example.com/test'),
      );
      expect(
        () => didKeyController.addServiceEndpoint(serviceEndpoint),
        throwsUnsupportedError,
      );
    });
  });
}
