import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DidKeyManager', () {
    late Wallet wallet;
    late DidStore store;
    late DidKeyManager manager;

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      store = InMemoryDidStore();
      manager = DidKeyManager(
        store: store,
        wallet: wallet,
      );
    });

    group('addVerificationMethod', () {
      test('should add verification method', () async {
        // Arrange
        final keyPair =
            await wallet.generateKey(keyId: 'test-key', keyType: KeyType.p256);

        // Act
        final result = await manager.addVerificationMethod(keyPair.id);
        final verificationMethodId = result.verificationMethodId;

        // Assert
        expect(verificationMethodId, startsWith('did:key:'));
        expect(verificationMethodId, contains('#'));
        final walletKeyId = await manager.getWalletKeyId(verificationMethodId);
        expect(walletKeyId, equals(keyPair.id));
      });

      test('should throw error when adding second key', () async {
        // Arrange
        final key1 =
            await wallet.generateKey(keyId: 'key-1', keyType: KeyType.p256);
        final key2 =
            await wallet.generateKey(keyId: 'key-2', keyType: KeyType.p256);
        await manager.addVerificationMethod(key1.id);

        // Act & Assert
        expect(
          () => manager.addVerificationMethod(key2.id),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.tooManyVerificationMethods.code,
            ),
          ),
        );
      });
    });

    group('getDidDocument', () {
      test('should create document from ed25519 key', () async {
        // Generate key
        final key = await wallet.generateKey(keyType: KeyType.ed25519);

        // Add verification method
        final result = await manager.addVerificationMethod(key.id);
        final vmId = result.verificationMethodId;

        // Get DID Document
        final didDocument = await manager.getDidDocument();

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

      test('should create proper verification methods for Ed25519+X25519 key',
          () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'ed25519-key-for-x',
          keyType: KeyType.ed25519,
        );
        await manager.addVerificationMethod(keyPair.id);

        // Act
        final document = await manager.getDidDocument();

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
          () => manager.getDidDocument(),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.verificationMethodNotFound.code,
            ),
          ),
        );
      });
    });

    group('Verification method purposes', () {
      test('should throw error when adding authentication', () async {
        // Arrange
        final keyPair =
            await wallet.generateKey(keyId: 'auth-key', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act & Assert
        expect(
          () => manager.addAuthentication(vmId),
          throwsUnsupportedError,
        );
      });

      test('should throw error when adding key agreement', () async {
        // Arrange
        final keyPair =
            await wallet.generateKey(keyId: 'ka-key', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act & Assert
        expect(
          () => manager.addKeyAgreement(vmId),
          throwsUnsupportedError,
        );
      });

      test('should throw error when adding capability invocation', () async {
        // Arrange
        final keyPair =
            await wallet.generateKey(keyId: 'ci-key', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act & Assert
        expect(
          () => manager.addCapabilityInvocation(vmId),
          throwsUnsupportedError,
        );
      });

      test('should throw error when adding capability delegation', () async {
        // Arrange
        final keyPair =
            await wallet.generateKey(keyId: 'cd-key', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act & Assert
        expect(
          () => manager.addCapabilityDelegation(vmId),
          throwsUnsupportedError,
        );
      });

      test('should throw error when adding assertion method', () async {
        // Arrange
        final keyPair =
            await wallet.generateKey(keyId: 'am-key', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act & Assert
        expect(
          () => manager.addAssertionMethod(vmId),
          throwsUnsupportedError,
        );
      });
    });

    group('Service endpoints', () {
      test('should throw error when adding service endpoint', () async {
        // Arrange
        final endpoint = ServiceEndpoint(
          id: '#service-1',
          type: const StringServiceType('MessagingService'),
          serviceEndpoint: const StringEndpoint('https://example.com'),
        );

        // Act & Assert
        expect(
          () => manager.addServiceEndpoint(endpoint),
          throwsA(isA<UnsupportedError>()),
        );
      });

      test('should throw error when removing service endpoint', () async {
        // Act & Assert
        expect(
          () => manager.removeServiceEndpoint('#service-1'),
          throwsA(isA<UnsupportedError>()),
        );
      });
    });

    group('Signing and verification', () {
      test('should sign and verify with did:key manager', () async {
        // Arrange
        final keyPair =
            await wallet.generateKey(keyId: 'sign-key', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;
        final data = Uint8List.fromList('Hello, World!'.codeUnits);

        // Act
        final signature = await manager.sign(data, vmId);
        final isValid = await manager.verify(data, signature, vmId);

        // Assert
        expect(isValid, isTrue);
      });

      test('should throw error when signing with unknown key', () async {
        // Arrange
        final data = Uint8List.fromList('Test data'.codeUnits);

        // Act & Assert
        expect(
          () => manager.sign(data, 'unknown-vm-id'),
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
        final keyPair = await wallet.generateKey(
            keyId: 'signer-key', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act
        final signer = await manager.getSigner(vmId);

        // Assert
        expect(signer.keyId, equals(vmId));
        expect(signer.signatureScheme, isNotNull);
        expect(signer.did, startsWith('did:key:'));
      });

      test('should sign with DID signer', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
            keyId: 'signer-key-2', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;
        final signer = await manager.getSigner(vmId);
        final data = Uint8List.fromList('Sign this'.codeUnits);

        // Act
        final signature = await signer.sign(data);
        final isValid = await manager.verify(data, signature, vmId);

        // Assert
        expect(isValid, isTrue);
      });
    });

    group('Key retrieval', () {
      test('should retrieve DID key pair', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
            keyId: 'retrieve-key', keyType: KeyType.p256);
        final result = await manager.addVerificationMethod(keyPair.id);
        final vmId = result.verificationMethodId;

        // Act
        final didKeyPair = await manager.getKey(vmId);

        // Assert
        expect(didKeyPair.keyPair.id, equals(keyPair.id));
        expect(didKeyPair.verificationMethodId, equals(vmId));
        expect(didKeyPair.didDocument?.id, startsWith('did:key:'));
      });

      test('should throw error when retrieving unknown key', () async {
        // Act & Assert
        expect(
          () => manager.getKey('unknown-vm-id'),
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

    group('Ed25519 key agreement mapping', () {
      test('should retrieve key pair by X25519 key agreement ID', () async {
        // Arrange - Create DID Manager with Ed25519 key
        final keyPair = await wallet.generateKey(
          keyId: 'ed25519-key-agreement-test',
          keyType: KeyType.ed25519,
        );
        await manager.addVerificationMethod(keyPair.id);

        // Act - Create DID Document
        final didDocument = await manager.getDidDocument();

        // Assert - Find key pair with didDocument.keyAgreement.first.id
        expect(didDocument.keyAgreement, hasLength(1));
        final keyAgreementId = didDocument.keyAgreement.first.id;

        // Should be able to retrieve the wallet key ID using the X25519 key agreement ID
        final walletKeyId = await manager.getWalletKeyId(keyAgreementId);
        expect(walletKeyId, equals(keyPair.id));

        // Should be able to retrieve the key pair using the wallet key ID
        final retrievedKeyPair = await manager.getKeyPair(walletKeyId!);
        expect(retrievedKeyPair.id, equals(keyPair.id));
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
        final vmId = await manager.buildVerificationMethodId(keyPair.publicKey);

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
        final vmId = await manager.buildVerificationMethodId(keyPair.publicKey);

        // Assert
        expect(vmId,
            matches(RegExp(r'^did:key:z6Mk[a-zA-Z0-9]+#z6Mk[a-zA-Z0-9]+$')));
      });
    });
  });
}
