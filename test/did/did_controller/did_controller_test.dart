import 'dart:typed_data';

import 'package:ssi/src/did/public_key_utils.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

// Mock implementation of DidController for testing abstract functionality
class MockDidController extends DidController {
  String? _currentDid;

  // Track verification method IDs for test purposes
  final Map<String, String> _walletKeyToVmId = {};

  MockDidController({
    required super.store,
    required super.wallet,
  });

  void setCurrentDid(String did) {
    _currentDid = did;
  }

  @override
  Future<DidDocument> getDidDocument() async {
    if (_currentDid == null) {
      throw SsiException(
        message: 'No DID set for mock controller',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // Create a simple DID document with verification methods
    final verificationMethods = <EmbeddedVerificationMethod>[];
    final authenticationRefs = <String>[];
    final keyAgreementRefs = <String>[];
    final capabilityInvocationRefs = <String>[];
    final capabilityDelegationRefs = <String>[];
    final assertionMethodRefs = <String>[];

    // Get all verification method IDs from store
    final vmIds = await store.verificationMethodIds;

    for (final vmId in vmIds) {
      final walletKeyId = await store.getWalletKeyId(vmId);
      if (walletKeyId != null) {
        final publicKey = await wallet.getPublicKey(walletKeyId);
        final vm = VerificationMethodJwk(
          id: vmId,
          controller: _currentDid!,
          type: 'JsonWebKey2020',
          publicKeyJwk: Jwk.fromJson(
              multiKeyToJwk(toMultikey(publicKey.bytes, publicKey.type))),
        );
        verificationMethods.add(vm);
      }
    }

    // Add references based on store
    authenticationRefs.addAll(await store.authentication);
    keyAgreementRefs.addAll(await store.keyAgreement);
    capabilityInvocationRefs.addAll(await store.capabilityInvocation);
    capabilityDelegationRefs.addAll(await store.capabilityDelegation);
    assertionMethodRefs.addAll(await store.assertionMethod);

    // Return document with proper references
    return DidDocument.create(
      id: _currentDid!,
      verificationMethod: verificationMethods,
      authentication: authenticationRefs,
      assertionMethod: assertionMethodRefs,
      keyAgreement: keyAgreementRefs,
      capabilityInvocation: capabilityInvocationRefs,
      capabilityDelegation: capabilityDelegationRefs,
    );
  }

  @override
  Future<String> buildVerificationMethodId(PublicKey publicKey) async {
    if (_currentDid == null) {
      throw SsiException(
        message: 'No DID set for mock controller',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // Create a simple verification method ID based on the public key type
    publicKey.type.toString().split('.').last.toLowerCase();
    final index = _walletKeyToVmId.length + 1;
    return '$_currentDid#key-$index';
  }

  // Helper method to track VM IDs for test purposes
  @override
  Future<String> addVerificationMethod(String walletKeyId) async {
    final vmId = await super.addVerificationMethod(walletKeyId);
    _walletKeyToVmId[walletKeyId] = vmId;
    return vmId;
  }
}

void main() {
  group('DidController', () {
    late Wallet wallet;
    late DidStore store;
    late MockDidController controller;

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      store = InMemoryDidStore();
      controller = MockDidController(
        store: store,
        wallet: wallet,
      );
      controller.setCurrentDid('did:test:12345');
    });

    group('getVerificationMethods', () {
      test('should filter verification methods by purpose', () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'auth-key-1');
        final keyAgreementKey =
            await wallet.generateKey(keyId: 'key-agreement-1');

        final authVmId = await controller.addVerificationMethod(authKey.id);
        final keyAgrVmId =
            await controller.addVerificationMethod(keyAgreementKey.id);
        await controller.addAuthentication(authVmId);
        await controller.addKeyAgreement(keyAgrVmId);

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.authentication.length, 1);
        expect(document.keyAgreement.length, 1);
        expect(document.verificationMethod.length, 2);
      });

      test('should handle multiple keys for same purpose', () async {
        // Arrange
        final authKey1 = await wallet.generateKey(keyId: 'auth-key-1');
        final authKey2 = await wallet.generateKey(keyId: 'auth-key-2');

        final authVmId1 = await controller.addVerificationMethod(authKey1.id);
        final authVmId2 = await controller.addVerificationMethod(authKey2.id);
        await controller.addAuthentication(authVmId1);
        await controller.addAuthentication(authVmId2);

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.authentication.length, 2);
        expect(document.verificationMethod.length, 2);
      });

      test('should handle all verification method purposes', () async {
        // Arrange
        final authKey = await wallet.generateKey(keyId: 'auth-key');
        final keyAgreementKey =
            await wallet.generateKey(keyId: 'key-agreement');
        final capInvocationKey =
            await wallet.generateKey(keyId: 'cap-invocation');
        final capDelegationKey =
            await wallet.generateKey(keyId: 'cap-delegation');
        final assertionKey = await wallet.generateKey(keyId: 'assertion');

        final authVmId = await controller.addVerificationMethod(authKey.id);
        final keyAgrVmId =
            await controller.addVerificationMethod(keyAgreementKey.id);
        final capInvVmId =
            await controller.addVerificationMethod(capInvocationKey.id);
        final capDelVmId =
            await controller.addVerificationMethod(capDelegationKey.id);
        final assertVmId =
            await controller.addVerificationMethod(assertionKey.id);

        await controller.addAuthentication(authVmId);
        await controller.addKeyAgreement(keyAgrVmId);
        await controller.addCapabilityInvocation(capInvVmId);
        await controller.addCapabilityDelegation(capDelVmId);
        await controller.addAssertionMethod(assertVmId);

        // Act
        final document = await controller.getDidDocument();

        // Assert
        expect(document.authentication.length, 1);
        expect(document.keyAgreement.length, 1);
        expect(document.capabilityInvocation.length, 1);
        expect(document.capabilityDelegation.length, 1);
        expect(document.assertionMethod.length, 1);
        expect(document.verificationMethod.length, 5);
      });
    });

    group('getKeyByVerificationMethodId', () {
      test('should retrieve key pair by verification method ID', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'test-key-1');
        final vmId = await controller.addVerificationMethod(keyPair.id);
        await controller.addAuthentication(vmId);
        await controller.getDidDocument(); // Initialize document

        // Act
        final retrievedKey = await controller.getKey(vmId);

        // Assert
        expect(retrievedKey.keyPair.id, keyPair.id);
        expect(retrievedKey.verificationMethodId, vmId);
        expect(retrievedKey.didDocument, isNotNull);
      });

      test('should throw error for invalid verification method ID', () async {
        // Act & Assert
        expect(
          () => controller.getKey('did:test:12345#invalid-key'),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.keyNotFound.code,
            ),
          ),
        );
      });

      test('should handle multiple keys with different IDs', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'key-1');
        final key2 = await wallet.generateKey(keyId: 'key-2');

        final vmId1 = await controller.addVerificationMethod(key1.id);
        final vmId2 = await controller.addVerificationMethod(key2.id);
        await controller.addAuthentication(vmId1);
        await controller.addKeyAgreement(vmId2);
        await controller.getDidDocument(); // Initialize document

        // Act
        final retrieved1 = await controller.getKey(vmId1);
        final retrieved2 = await controller.getKey(vmId2);

        // Assert
        expect(retrieved1.keyPair.id, key1.id);
        expect(retrieved2.keyPair.id, key2.id);
        expect(vmId1, isNot(equals(vmId2)));
      });
    });

    group('mapDidVerificationMethodIdToWalletKeyId', () {
      test('should map verification method ID to wallet key ID', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'wallet-key-123');
        final vmId = await controller.addVerificationMethod(keyPair.id);
        await controller.addAuthentication(vmId);
        await controller.getDidDocument(); // Initialize document

        // Act
        final walletKeyId = await store.getWalletKeyId(vmId);

        // Assert
        expect(walletKeyId, 'wallet-key-123');
      });

      test('should return null for unmapped verification method ID', () async {
        // Act
        final walletKeyId =
            await store.getWalletKeyId('did:test:12345#unknown');

        // Assert
        expect(walletKeyId, isNull);
      });

      test('should handle multiple mappings', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'wallet-key-1');
        final key2 = await wallet.generateKey(keyId: 'wallet-key-2');

        final vmId1 = await controller.addVerificationMethod(key1.id);
        final vmId2 = await controller.addVerificationMethod(key2.id);
        await controller.addAuthentication(vmId1);
        await controller.addKeyAgreement(vmId2);
        await controller.getDidDocument(); // Initialize document

        // Act
        final walletKeyId1 = await store.getWalletKeyId(vmId1);
        final walletKeyId2 = await store.getWalletKeyId(vmId2);

        // Assert
        expect(walletKeyId1, 'wallet-key-1');
        expect(walletKeyId2, 'wallet-key-2');
      });
    });

    group('sign and verify', () {
      test('should sign data with verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'signing-key');
        final vmId = await controller.addVerificationMethod(keyPair.id);
        await controller.addAuthentication(vmId);
        await controller.getDidDocument(); // Initialize document
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);

        // Act
        final signature = await controller.sign(data, vmId);

        // Assert
        expect(signature, isNotEmpty);
        expect(signature.length, greaterThan(0));
      });

      test('should verify signature with verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'verify-key');
        final vmId = await controller.addVerificationMethod(keyPair.id);
        await controller.addAuthentication(vmId);
        await controller.getDidDocument(); // Initialize document
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final signature = await controller.sign(data, vmId);

        // Act
        final isValid = await controller.verify(data, signature, vmId);

        // Assert
        expect(isValid, isTrue);
      });

      test('should fail verification with wrong data', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'verify-key-2');
        final vmId = await controller.addVerificationMethod(keyPair.id);
        await controller.addAuthentication(vmId);
        await controller.getDidDocument(); // Initialize document
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final wrongData = Uint8List.fromList([6, 7, 8, 9, 10]);
        final signature = await controller.sign(data, vmId);

        // Act
        final isValid = await controller.verify(wrongData, signature, vmId);

        // Assert
        expect(isValid, isFalse);
      });

      test('should throw error for invalid verification method ID on sign',
          () async {
        // Arrange
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);

        // Act & Assert
        expect(
          () => controller.sign(data, 'did:test:12345#invalid'),
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

    group('getSigner', () {
      test('should create DID signer for verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'signer-key',
          keyType: KeyType.p256,
        );
        final vmId = await controller.addVerificationMethod(keyPair.id);
        await controller.addAuthentication(vmId);

        // Act
        final signer = await controller.getSigner(vmId);

        // Assert
        expect(signer.didKeyId, vmId);
        expect(signer.publicKey.type, keyPair.publicKey.type);
        expect(signer.did, 'did:test:12345');
      });

      test('should create signer with custom signature scheme', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'ed25519-key',
          keyType: KeyType.ed25519,
        );
        final vmId = await controller.addVerificationMethod(keyPair.id);
        await controller.addAuthentication(vmId);

        // Act
        final signer = await controller.getSigner(
          vmId,
          signatureScheme: SignatureScheme.eddsa_sha512,
        );

        // Assert
        expect(signer.signatureScheme, SignatureScheme.eddsa_sha512);
      });
    });

    group('addVerificationMethod variations', () {
      test('should add verification method and return ID', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'test-key');

        // Act
        final vmId = await controller.addVerificationMethod(keyPair.id);
        await controller.addAuthentication(vmId);

        // Assert
        final document = await controller.getDidDocument();
        expect(document.verificationMethod.length, 1);
        expect(document.authentication.length, 1);
        expect(document.authentication[0].id, vmId);
      });

      test('should handle all verification method purpose additions', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'key-1');
        final key2 = await wallet.generateKey(keyId: 'key-2');
        final key3 = await wallet.generateKey(keyId: 'key-3');
        final key4 = await wallet.generateKey(keyId: 'key-4');
        final key5 = await wallet.generateKey(keyId: 'key-5');

        // Act
        final vmId1 = await controller.addVerificationMethod(key1.id);
        final vmId2 = await controller.addVerificationMethod(key2.id);
        final vmId3 = await controller.addVerificationMethod(key3.id);
        final vmId4 = await controller.addVerificationMethod(key4.id);
        final vmId5 = await controller.addVerificationMethod(key5.id);

        await controller.addAuthentication(vmId1);
        await controller.addKeyAgreement(vmId2);
        await controller.addCapabilityInvocation(vmId3);
        await controller.addCapabilityDelegation(vmId4);
        await controller.addAssertionMethod(vmId5);

        // Assert
        final document = await controller.getDidDocument();
        expect(document.authentication.length, 1);
        expect(document.keyAgreement.length, 1);
        expect(document.capabilityInvocation.length, 1);
        expect(document.capabilityDelegation.length, 1);
        expect(document.assertionMethod.length, 1);
      });

      test('should throw error when adding with empty verification method ID',
          () async {
        // Act & Assert
        expect(
          () => controller.addAuthentication(''),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.other.code,
            ),
          ),
        );
      });
    });

    group('verification method references', () {
      test('should add and remove verification method references', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'ref-key');
        final vmId = await controller.addVerificationMethod(keyPair.id);

        // Act - Add references
        await controller.addAuthentication(vmId);
        await controller.addKeyAgreement(vmId);
        await controller.addCapabilityInvocation(vmId);
        await controller.addCapabilityDelegation(vmId);
        await controller.addAssertionMethod(vmId);

        // Assert - All added
        var document = await controller.getDidDocument();
        expect(document.authentication.any((vm) => vm.id == vmId), isTrue);
        expect(document.keyAgreement.any((vm) => vm.id == vmId), isTrue);
        expect(
            document.capabilityInvocation.any((vm) => vm.id == vmId), isTrue);
        expect(
            document.capabilityDelegation.any((vm) => vm.id == vmId), isTrue);
        expect(document.assertionMethod.any((vm) => vm.id == vmId), isTrue);

        // Act - Remove references
        await controller.removeAuthentication(vmId);
        await controller.removeKeyAgreement(vmId);
        await controller.removeCapabilityInvocation(vmId);
        await controller.removeCapabilityDelegation(vmId);
        await controller.removeAssertionMethod(vmId);

        // Assert - All removed
        document = await controller.getDidDocument();
        expect(document.authentication.length, 0);
        expect(document.keyAgreement.length, 0);
        expect(document.capabilityInvocation.length, 0);
        expect(document.capabilityDelegation.length, 0);
        expect(document.assertionMethod.length, 0);
      });

      test('should use one verification method for multiple purposes',
          () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'multi-purpose-key');
        final vmId = await controller.addVerificationMethod(keyPair.id);

        // Act
        await controller.addAuthentication(vmId);
        await controller.addKeyAgreement(vmId);
        await controller.addCapabilityInvocation(vmId);
        await controller.addCapabilityDelegation(vmId);
        await controller.addAssertionMethod(vmId);

        // Assert
        final document = await controller.getDidDocument();
        expect(document.verificationMethod.length, 1);
        expect(document.authentication.any((vm) => vm.id == vmId), isTrue);
        expect(document.keyAgreement.any((vm) => vm.id == vmId), isTrue);
        expect(
            document.capabilityInvocation.any((vm) => vm.id == vmId), isTrue);
        expect(
            document.capabilityDelegation.any((vm) => vm.id == vmId), isTrue);
        expect(document.assertionMethod.any((vm) => vm.id == vmId), isTrue);
      });

      test(
          'should throw error when adding reference for unmapped verification method',
          () {
        // Act & Assert
        expect(
          () => controller.addAuthentication('did:test:12345#unmapped'),
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
  });
}
