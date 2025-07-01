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
      test('should add single verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'test-key');

        // Act
        final verificationMethodId =
            await controller.addVerificationMethod(keyPair.id);

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
      test('should create document from P256 key', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'p256-key',
          keyType: KeyType.p256,
        );
        await controller.addVerificationMethod(keyPair.id);

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.id, startsWith('did:key:zDn'));
        expect(document.verificationMethod.length, 1);
        expect(document.verificationMethod[0].type, 'P256Key2021');
        expect(document.authentication.length, 1);
        expect(document.assertionMethod.length, 1);
        expect(document.keyAgreement.length, 1);
        expect(document.capabilityInvocation.length, 1);
        expect(document.capabilityDelegation.length, 1);
      });

      test('should create document from ED25519 key', () async {
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
        expect(document.verificationMethod.length, 2); // ED25519 + X25519
        expect(
            document.verificationMethod[0].type, 'Ed25519VerificationKey2020');
        expect(document.authentication.length, 1);
        expect(document.assertionMethod.length, 1);
        expect(document.keyAgreement.length, 1);
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
      test('should throw error when adding authentication', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'auth-key');
        final vmId = await controller.addVerificationMethod(keyPair.id);

        // Act & Assert
        expect(
          () => controller.addAuthentication(vmId),
          throwsA(isA<UnsupportedError>()),
        );
      });

      test('should throw error when adding key agreement', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'ka-key');
        final vmId = await controller.addVerificationMethod(keyPair.id);

        // Act & Assert
        expect(
          () => controller.addKeyAgreement(vmId),
          throwsA(isA<UnsupportedError>()),
        );
      });

      test('should throw error when adding capability invocation', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'ci-key');
        final vmId = await controller.addVerificationMethod(keyPair.id);

        // Act & Assert
        expect(
          () => controller.addCapabilityInvocation(vmId),
          throwsA(isA<UnsupportedError>()),
        );
      });

      test('should throw error when adding capability delegation', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'cd-key');
        final vmId = await controller.addVerificationMethod(keyPair.id);

        // Act & Assert
        expect(
          () => controller.addCapabilityDelegation(vmId),
          throwsA(isA<UnsupportedError>()),
        );
      });

      test('should throw error when adding assertion method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'am-key');
        final vmId = await controller.addVerificationMethod(keyPair.id);

        // Act & Assert
        expect(
          () => controller.addAssertionMethod(vmId),
          throwsA(isA<UnsupportedError>()),
        );
      });
    });

    group('Service endpoints', () {
      test('should throw error when adding service endpoint', () async {
        // Arrange
        final endpoint = ServiceEndpoint(
          id: '#service-1',
          type: 'MessagingService',
          serviceEndpoint: StringEndpoint('https://example.com'),
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
        final vmId = await controller.addVerificationMethod(keyPair.id);
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
        final vmId = await controller.addVerificationMethod(keyPair.id);

        // Act
        final signer = await controller.getSigner(vmId);

        // Assert
        expect(signer.didKeyId, equals(vmId));
        expect(signer.signatureScheme, isNotNull);
        expect(signer.did, startsWith('did:key:'));
      });

      test('should sign with DID signer', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'signer-key-2');
        final vmId = await controller.addVerificationMethod(keyPair.id);
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
        final vmId = await controller.addVerificationMethod(keyPair.id);

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

      test('should build proper ID for ED25519 key', () async {
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
