import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

// Mock implementation of DidController for testing abstract functionality
class MockDidController extends DidController {
  String? _currentDid;

  MockDidController({
    required super.keyMapping,
    required super.wallet,
  });

  void setCurrentDid(String did) {
    _currentDid = did;
  }

  @override
  Future<DidDocument> createOrUpdateDocument() async {
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

    // Create verification methods for all keys
    final allKeys = <String>{};
    for (final keyIds in keysByPurpose.values) {
      allKeys.addAll(keyIds);
    }

    var index = 0;
    for (final keyId in allKeys) {
      index++;
      final publicKey = await wallet.getPublicKey(keyId);
      final vmId = '$_currentDid#key-$index';
      final vm = VerificationMethodJwk(
        id: vmId,
        controller: _currentDid!,
        type: 'JsonWebKey2020',
        publicKeyJwk: Jwk.fromJson(
            multiKeyToJwk(toMultikey(publicKey.bytes, publicKey.type))),
      );
      verificationMethods.add(vm);
      keyMapping.setMapping(vm.id, keyId);

      // Add to appropriate purpose arrays based on keysByPurpose
      if (keysByPurpose[VerificationMethodPurpose.authentication]
              ?.contains(keyId) ??
          false) {
        authenticationRefs.add(vmId);
      }
      if (keysByPurpose[VerificationMethodPurpose.keyAgreement]
              ?.contains(keyId) ??
          false) {
        keyAgreementRefs.add(vmId);
      }
      if (keysByPurpose[VerificationMethodPurpose.capabilityInvocation]
              ?.contains(keyId) ??
          false) {
        capabilityInvocationRefs.add(vmId);
      }
      if (keysByPurpose[VerificationMethodPurpose.capabilityDelegation]
              ?.contains(keyId) ??
          false) {
        capabilityDelegationRefs.add(vmId);
      }
      if (keysByPurpose[VerificationMethodPurpose.assertionMethod]
              ?.contains(keyId) ??
          false) {
        assertionMethodRefs.add(vmId);
      }
    }

    // Return document with proper references
    return DidDocument.create(
      id: _currentDid!,
      verificationMethod: verificationMethods,
      // Include the references that match our verification methods
      authentication: authenticationRefs,
      assertionMethod: assertionMethodRefs,
      keyAgreement: keyAgreementRefs,
      capabilityInvocation: capabilityInvocationRefs,
      capabilityDelegation: capabilityDelegationRefs,
    );
  }

  @override
  Future<String> findVerificationMethodId(String keyId) async {
    if (_currentDid == null) {
      throw SsiException(
        message: 'No DID set for mock controller',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // Find the index of this key
    final allKeys = <String>{};
    for (final keyIds in keysByPurpose.values) {
      allKeys.addAll(keyIds);
    }

    final keyList = allKeys.toList();
    final index = keyList.indexOf(keyId);
    if (index == -1) {
      throw SsiException(
        message: 'Key not found: $keyId',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    return '$_currentDid#key-${index + 1}';
  }
}

void main() {
  group('DidController', () {
    late Wallet wallet;
    late DiDControllerStore keyMapping;
    late MockDidController controller;

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      keyMapping = DefaultDiDControllerStore();
      controller = MockDidController(
        keyMapping: keyMapping,
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

        controller.addAuthenticationKey(authKey.id);
        controller.addKeyAgreementKey(keyAgreementKey.id);

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

        controller.addAuthenticationKey(authKey1.id);
        controller.addAuthenticationKey(authKey2.id);

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

        controller.addAuthenticationKey(authKey.id);
        controller.addKeyAgreementKey(keyAgreementKey.id);
        controller.addCapabilityInvocationKey(capInvocationKey.id);
        controller.addCapabilityDelegationKey(capDelegationKey.id);
        controller.addAssertionMethodKey(assertionKey.id);

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
        controller.addAuthenticationKey(keyPair.id);
        await controller.getDidDocument(); // Initialize document
        final vmId = await controller.findVerificationMethodId(keyPair.id);

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

        controller.addAuthenticationKey(key1.id);
        controller.addKeyAgreementKey(key2.id);
        await controller.getDidDocument(); // Initialize document

        final vmId1 = await controller.findVerificationMethodId(key1.id);
        final vmId2 = await controller.findVerificationMethodId(key2.id);

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
        controller.addAuthenticationKey(keyPair.id);
        await controller.getDidDocument(); // Initialize document
        final vmId = await controller.findVerificationMethodId(keyPair.id);

        // Act
        final walletKeyId = keyMapping.getWalletKeyId(vmId);

        // Assert
        expect(walletKeyId, 'wallet-key-123');
      });

      test('should return null for unmapped verification method ID', () {
        // Act
        final walletKeyId = keyMapping.getWalletKeyId('did:test:12345#unknown');

        // Assert
        expect(walletKeyId, isNull);
      });

      test('should handle multiple mappings', () async {
        // Arrange
        final key1 = await wallet.generateKey(keyId: 'wallet-key-1');
        final key2 = await wallet.generateKey(keyId: 'wallet-key-2');

        controller.addAuthenticationKey(key1.id);
        controller.addKeyAgreementKey(key2.id);
        await controller.getDidDocument(); // Initialize document

        final vmId1 = await controller.findVerificationMethodId(key1.id);
        final vmId2 = await controller.findVerificationMethodId(key2.id);

        // Act
        final walletKeyId1 = keyMapping.getWalletKeyId(vmId1);
        final walletKeyId2 = keyMapping.getWalletKeyId(vmId2);

        // Assert
        expect(walletKeyId1, 'wallet-key-1');
        expect(walletKeyId2, 'wallet-key-2');
      });
    });

    group('sign and verify', () {
      test('should sign data with verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'signing-key');
        controller.addAuthenticationKey(keyPair.id);
        await controller.getDidDocument(); // Initialize document
        final vmId = await controller.findVerificationMethodId(keyPair.id);
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
        controller.addAuthenticationKey(keyPair.id);
        await controller.getDidDocument(); // Initialize document
        final vmId = await controller.findVerificationMethodId(keyPair.id);
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
        controller.addAuthenticationKey(keyPair.id);
        await controller.getDidDocument(); // Initialize document
        final vmId = await controller.findVerificationMethodId(keyPair.id);
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final wrongData = Uint8List.fromList([6, 7, 8, 9, 10]);
        final signature = await controller.sign(data, vmId);

        // Act
        final isValid = await controller.verify(wrongData, signature, vmId);

        // Assert
        expect(isValid, isFalse);
      });

      test('should throw error for unknown verification method when signing',
          () async {
        // Arrange
        final data = Uint8List.fromList([1, 2, 3]);

        // Act & Assert
        expect(
          () => controller.sign(data, 'did:test:12345#unknown'),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.keyNotFound.code,
            ),
          ),
        );
      });

      test('should sign and verify with different key types', () async {
        // Test with P256
        final p256Key = await wallet.generateKey(
          keyId: 'p256-key',
          keyType: KeyType.p256,
        );
        controller.addAuthenticationKey(p256Key.id);
        await controller.getDidDocument();
        final p256VmId = await controller.findVerificationMethodId(p256Key.id);

        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final p256Signature = await controller.sign(data, p256VmId);
        final p256Valid =
            await controller.verify(data, p256Signature, p256VmId);

        expect(p256Valid, isTrue);

        // Test with ED25519
        final ed25519Key = await wallet.generateKey(
          keyId: 'ed25519-key',
          keyType: KeyType.ed25519,
        );
        controller.addAuthenticationKey(ed25519Key.id);
        await controller.getDidDocument();
        final ed25519VmId =
            await controller.findVerificationMethodId(ed25519Key.id);

        final ed25519Signature = await controller.sign(data, ed25519VmId);
        final ed25519Valid =
            await controller.verify(data, ed25519Signature, ed25519VmId);

        expect(ed25519Valid, isTrue);
      });
    });

    group('verification method references', () {
      test('should add authentication verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'auth-key');

        // Act
        final vmId = await controller.addAuthenticationVerificationMethod(
          keyPair.publicKey.type,
          keyPair.id,
        );
        final document = await controller.getDidDocument();

        // Assert
        expect(vmId, contains('#'));
        expect(document.authentication.length, 1);
        expect(keyMapping.getWalletKeyId(vmId), keyPair.id);
      });

      test('should add key agreement verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'ka-key');

        // Act
        final vmId = await controller.addKeyAgreementVerificationMethod(
          keyPair.publicKey.type,
          keyPair.id,
        );
        final document = await controller.getDidDocument();

        // Assert
        expect(vmId, contains('#'));
        expect(document.keyAgreement.length, 1);
        expect(keyMapping.getWalletKeyId(vmId), keyPair.id);
      });

      test('should add capability invocation verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'ci-key');

        // Act
        final vmId = await controller.addCapabilityInvocationVerificationMethod(
          keyPair.publicKey.type,
          keyPair.id,
        );
        final document = await controller.getDidDocument();

        // Assert
        expect(vmId, contains('#'));
        expect(document.capabilityInvocation.length, 1);
        expect(keyMapping.getWalletKeyId(vmId), keyPair.id);
      });

      test('should add capability delegation verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'cd-key');

        // Act
        final vmId = await controller.addCapabilityDelegationVerificationMethod(
          keyPair.publicKey.type,
          keyPair.id,
        );
        final document = await controller.getDidDocument();

        // Assert
        expect(vmId, contains('#'));
        expect(document.capabilityDelegation.length, 1);
        expect(keyMapping.getWalletKeyId(vmId), keyPair.id);
      });

      test('should add assertion method verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'am-key');

        // Act
        final vmId = await controller.addAssertionMethodVerificationMethod(
          keyPair.publicKey.type,
          keyPair.id,
        );
        final document = await controller.getDidDocument();

        // Assert
        expect(vmId, contains('#'));
        expect(document.assertionMethod.length, 1);
        expect(keyMapping.getWalletKeyId(vmId), keyPair.id);
      });

      test('should throw error for non-existent wallet key', () async {
        // Act & Assert
        expect(
          () => controller.addAuthenticationVerificationMethod(
            KeyType.p256,
            'non-existent-key',
          ),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.keyNotFound.code,
            ),
          ),
        );
      });

      test('should add and remove verification method references', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'ref-key');
        controller.addAuthenticationKey(keyPair.id);
        await controller.getDidDocument();
        final vmId = await controller.findVerificationMethodId(keyPair.id);

        // Act - Add references
        controller.addAuthenticationVerificationMethodReference(vmId);
        controller.addKeyAgreementVerificationMethodReference(vmId);
        controller.addCapabilityInvocationVerificationMethodReference(vmId);
        controller.addCapabilityDelegationVerificationMethodReference(vmId);
        controller.addAssertionMethodVerificationMethodReference(vmId);

        var document = await controller.getDidDocument();

        // Assert - All references added
        // Note: Authentication already has the key from addAuthenticationKey,
        // so adding the reference doesn't increase the count (no duplicates)
        expect(document.authentication.length, 1); // No duplicates
        expect(document.keyAgreement.length, 1);
        expect(document.capabilityInvocation.length, 1);
        expect(document.capabilityDelegation.length, 1);
        expect(document.assertionMethod.length, 1);

        // Act - Remove references
        controller.removeAuthenticationVerificationMethodReference(vmId);
        controller.removeKeyAgreementVerificationMethodReference(vmId);
        controller.removeCapabilityInvocationVerificationMethodReference(vmId);
        controller.removeCapabilityDelegationVerificationMethodReference(vmId);
        controller.removeAssertionMethodVerificationMethodReference(vmId);

        document = await controller.getDidDocument();

        // Assert - References removed
        expect(document.authentication.length,
            1); // Original authentication key remains
        expect(document.keyAgreement.length, 0);
        expect(document.capabilityInvocation.length, 0);
        expect(document.capabilityDelegation.length, 0);
        expect(document.assertionMethod.length, 0);
      });

      test('should remove all verification method references at once',
          () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'all-ref-key');
        controller.addAuthenticationKey(keyPair.id);
        await controller.getDidDocument();
        final vmId = await controller.findVerificationMethodId(keyPair.id);

        // Add to all purposes
        controller.addAuthenticationVerificationMethodReference(vmId);
        controller.addKeyAgreementVerificationMethodReference(vmId);
        controller.addCapabilityInvocationVerificationMethodReference(vmId);
        controller.addCapabilityDelegationVerificationMethodReference(vmId);
        controller.addAssertionMethodVerificationMethodReference(vmId);

        // Act
        controller.removeAllVerificationMethodReferences(vmId);
        final document = await controller.getDidDocument();

        // Assert - All references removed
        expect(document.authentication.length, 1); // Only original remains
        expect(document.keyAgreement.length, 0);
        expect(document.capabilityInvocation.length, 0);
        expect(document.capabilityDelegation.length, 0);
        expect(document.assertionMethod.length, 0);
      });

      test(
          'should throw error when adding reference for unmapped verification method',
          () {
        // Act & Assert
        expect(
          () => controller.addAuthenticationVerificationMethodReference(
              'did:test:12345#unmapped'),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.keyNotFound.code,
            ),
          ),
        );
      });

      test('should throw error for empty verification method ID', () {
        // Act & Assert
        expect(
          () => controller.addAuthenticationVerificationMethodReference(''),
          throwsA(
            isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains('cannot be empty'),
            ),
          ),
        );

        expect(
          () => controller.removeAuthenticationVerificationMethodReference(''),
          throwsA(
            isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains('cannot be empty'),
            ),
          ),
        );
      });
    });

    group('getSigner', () {
      test('should get DID signer for verification method', () async {
        // Arrange
        final keyPair = await wallet.generateKey(keyId: 'signer-key');
        controller.addAuthenticationKey(keyPair.id);
        await controller.getDidDocument();
        final vmId = await controller.findVerificationMethodId(keyPair.id);

        // Act
        final signer = await controller.getSigner(vmId);

        // Assert
        expect(signer.didKeyId, vmId);
        expect(signer.signatureScheme, isNotNull);
      });

      test('should get signer with custom signature scheme', () async {
        // Arrange
        final keyPair = await wallet.generateKey(
          keyId: 'signer-key-2',
          keyType: KeyType.p256,
        );
        controller.addAuthenticationKey(keyPair.id);
        await controller.getDidDocument();
        final vmId = await controller.findVerificationMethodId(keyPair.id);

        // Act
        final signer = await controller.getSigner(
          vmId,
          signatureScheme: SignatureScheme.ecdsa_p256_sha256,
        );

        // Assert
        expect(signer.signatureScheme, SignatureScheme.ecdsa_p256_sha256);
      });

      test(
          'should throw error for unknown verification method when getting signer',
          () async {
        // Act & Assert
        expect(
          () => controller.getSigner('did:test:12345#unknown-signer'),
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

    group('error cases', () {
      test('should throw error when adding empty key ID', () {
        // Act & Assert
        expect(
          () => controller.addAuthenticationKey(''),
          throwsA(
            isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains('cannot be empty'),
            ),
          ),
        );

        expect(
          () => controller.addKeyAgreementKey(''),
          throwsA(
            isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains('cannot be empty'),
            ),
          ),
        );

        expect(
          () => controller.addCapabilityInvocationKey(''),
          throwsA(
            isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains('cannot be empty'),
            ),
          ),
        );

        expect(
          () => controller.addCapabilityDelegationKey(''),
          throwsA(
            isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains('cannot be empty'),
            ),
          ),
        );

        expect(
          () => controller.addAssertionMethodKey(''),
          throwsA(
            isA<SsiException>().having(
              (e) => e.message,
              'message',
              contains('cannot be empty'),
            ),
          ),
        );
      });
    });
  });
}
