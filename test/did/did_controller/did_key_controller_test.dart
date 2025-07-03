import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidKeyController', () {
    late Wallet wallet;
    late DidStore store;
    late DidKeyController controller;

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      store = InMemoryDidStore();
      controller = DidKeyController(
        store: store,
        wallet: wallet,
      );
    });

    group('addVerificationMethod', () {
      test('should add verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'test-key');

        // Act
        final result = await controller.addVerificationMethod(keyPair.id);
        final verificationMethodId = result.verificationMethodId;

        // Assert
        expect(verificationMethodId, startsWith('did:key:'));
        expect(verificationMethodId, contains('#'));
        final walletKeyId =
            await controller.getWalletKeyId(verificationMethodId);
        expect(walletKeyId, equals(keyPair.id));
      });

      test('should throw error when adding second key', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'key-1');
        final key2 = await wallet.generateKey(keyId: 'key-2');
        await controller.addVerificationMethod(key1.id);

        // Act & Assert
        expect(
          () => controller.addVerificationMethod(key2.id),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.unsupportedNumberOfKeys.code,
            ),
          ),
        );
      });
    });

    group('getDidDocument', () {
      test('should create document from ed25519 key', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'ed25519-key-p256-test',
          keyType: KeyType.ed25519,
        );
        await controller.addVerificationMethod(keyPair.id);

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.id, startsWith('did:key:z6Mk'));
        expect(document.verificationMethod.length, 2);
        expect(
            document.verificationMethod
                .any((vm) => vm.type == 'Ed25519VerificationKey2020'),
            isTrue);
        expect(document.authentication.length, 1);
        expect(document.assertionMethod.length, 1);
        expect(document.keyAgreement.length, 1);
        expect(document.capabilityInvocation.length, 1);
        expect(document.capabilityDelegation.length, 1);
      });

      test('should create document from Ed25519 key', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'ed25519-key',
          keyType: KeyType.ed25519,
        );
        await controller.addVerificationMethod(keyPair.id);

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.id, startsWith('did:key:z6Mk'));
        expect(document.verificationMethod.length, 2); // Ed25519 + X25519
        expect(
            document.verificationMethod[0].type, 'Ed25519VerificationKey2020');
        expect(document.authentication.length, 1);
        expect(document.assertionMethod.length, 1);
        expect(document.keyAgreement.length, 1);
        expect(document.capabilityInvocation.length, 1);
        expect(document.capabilityDelegation.length, 1);
      });

      test('should create proper verification methods for Ed25519+X25519 key',
          () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'ed25519-key-for-x',
          keyType: KeyType.ed25519,
        );
        await controller.addVerificationMethod(keyPair.id);

        // Act
        final document = await controller.getDidDocument();

        // Assert
        final edVm = document.verificationMethod
            .firstWhere((vm) => vm.type == 'Ed25519VerificationKey2020');
        final xVm = document.verificationMethod
            .firstWhere((vm) => vm.type == 'X25519KeyAgreementKey2020');

        final did = document.id;
        expect(did, startsWith('did:key:z6Mk'));

        // Ed25519 VM ID should be did#did-fragment
        expect(edVm.id, '$did#${did.split(':').last}');

        // X25519 VM ID should be did#x25519-fragment
        expect(xVm.id, startsWith('$did#z6LS'));
        expect(xVm.id, isNot('$did#${did.split(':').last}'));
      });

      test('should throw error when no key is added', () async {
        // Act & Assert
        expect(
          () => controller.getDidDocument(),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.unsupportedNumberOfKeys.code,
            ),
          ),
        );
      });
    });

    group('Verification method purposes', () {
      test('should not throw when adding authentication', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'auth-key');
        final result = await controller.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act & Assert
        expect(
          () => controller.addAuthentication(vmId),
          throwsUnsupportedError,
        );
      });

      test('should not throw when adding key agreement', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'ka-key');
        final result = await controller.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act & Assert
        expect(
          () => controller.addKeyAgreement(vmId),
          throwsUnsupportedError,
        );
      });

      test('should not throw when adding capability invocation', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'ci-key');
        final result = await controller.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act & Assert
        expect(
          () => controller.addCapabilityInvocation(vmId),
          throwsUnsupportedError,
        );
      });

      test('should not throw when adding capability delegation', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'cd-key');
        final result = await controller.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act & Assert
        expect(
          () => controller.addCapabilityDelegation(vmId),
          throwsUnsupportedError,
        );
      });

      test('should not throw when adding assertion method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'am-key');
        final result = await controller.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act & Assert
        expect(
          () => controller.addAssertionMethod(vmId),
          throwsUnsupportedError,
        );
      });
    });

    group('Service endpoints', () {
      test('should throw error when adding service endpoint', () async {
        // Arrange
        final endpoint = ServiceEndpoint(
          id: '#service-1',
          type: 'MessagingService',
          serviceEndpoint: const StringEndpoint('https://example.com'),
        );

        // Act & Assert
        expect(
          () => controller.addServiceEndpoint(endpoint),
          throwsA(isA<UnsupportedError>()),
        );
      });

      test('should throw error when removing service endpoint', () async {
        // Act & Assert
        expect(
          () => controller.removeServiceEndpoint('#service-1'),
          throwsA(isA<UnsupportedError>()),
        );
      });
    });

    group('Signing and verification', () {
      test('should sign and verify with did:key controller', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'sign-key');
        final result = await controller.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;
        final data = Uint8List.fromList('Hello, World!'.codeUnits);

        // Act
        final signature = await controller.sign(data, vmId);
        final isValid = await controller.verify(data, signature, vmId);

        // Assert
        expect(isValid, isTrue);
      });

      test('should throw error when signing with unknown key', () async {
        // Arrange
        final data = Uint8List.fromList('Test data'.codeUnits);

        // Act & Assert
        expect(
          () => controller.sign(data, 'unknown-vm-id'),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.keyNotFound.code,
            ),
          ),
        );
      });
    });

    group('DID signer integration', () {
      test('should get DID signer', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'signer-key');
        final result = await controller.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act
        final signer = await controller.getSigner(vmId);

        // Assert
        expect(signer.keyId, equals(vmId));
        expect(signer.signatureScheme, isNotNull);
        expect(signer.did, startsWith('did:key:'));
      });

      test('should sign with DID signer', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'signer-key-2');
        final result = await controller.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;
        final signer = await controller.getSigner(vmId);
        final data = Uint8List.fromList('Sign this'.codeUnits);

        // Act
        final signature = await signer.sign(data);
        final isValid = await controller.verify(data, signature, vmId);

        // Assert
        expect(isValid, isTrue);
      });
    });

    group('Key retrieval', () {
      test('should retrieve DID key pair', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'retrieve-key');
        final result = await controller.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act
        final didKeyPair = await controller.getKey(vmId);

        // Assert
        expect(didKeyPair.keyPair.id, equals(keyPair.id));
        expect(didKeyPair.verificationMethodId, equals(vmId));
        expect(didKeyPair.didDocument?.id, startsWith('did:key:'));
      });

      test('should throw error when retrieving unknown key', () async {
        // Act & Assert
        expect(
          () => controller.getKey('unknown-vm-id'),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.keyNotFound.code,
            ),
          ),
        );
      });
    });

    group('buildVerificationMethodId', () {
      test('should build proper ID for P256 key', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'p256-id-test',
          keyType: KeyType.p256,
        );

        // Act
        final vmId =
            await controller.buildVerificationMethodId(keyPair.publicKey);

        // Assert
        expect(vmId,
            matches(RegExp(r'^did:key:zDn[a-zA-Z0-9]+#zDn[a-zA-Z0-9]+$')));
      });

      test('should build proper ID for Ed25519 key', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'ed25519-id-test',
          keyType: KeyType.ed25519,
        );

        // Act
        final vmId =
            await controller.buildVerificationMethodId(keyPair.publicKey);

        // Assert
        expect(vmId,
            matches(RegExp(r'^did:key:z6Mk[a-zA-Z0-9]+#z6Mk[a-zA-Z0-9]+$')));
      });
    });
  });
}
