import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('InMemoryDidStore', () {
    late InMemoryDidStore store;

    setUp(() {
      store = InMemoryDidStore();
    });

    group('Map/get/remove operations', () {
      test('should set and get mapping', () async {
        // Arrange
        const didKeyId =
            'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
        const walletKeyId = 'wallet-key-123';

        // Act
        await store.setMapping(didKeyId, walletKeyId);
        final retrieved = await store.getWalletKeyId(didKeyId);

        // Assert
        expect(retrieved, walletKeyId);
      });

      test('should return null for non-existent mapping', () async {
        // Act
        final retrieved = await store.getWalletKeyId('did:key:unknown#key');

        // Assert
        expect(retrieved, isNull);
      });

      test('should remove mapping', () async {
        // Arrange
        const didKeyId = 'did:peer:2.Ez...#key-1';
        const walletKeyId = 'wallet-key-456';
        await store.setMapping(didKeyId, walletKeyId);

        // Act
        await store.removeMapping(didKeyId);
        final retrieved = await store.getWalletKeyId(didKeyId);

        // Assert
        expect(retrieved, isNull);
      });

      test('should overwrite existing mapping', () async {
        // Arrange
        const didKeyId = 'did:key:z6Mk...#key';
        const walletKeyId1 = 'wallet-key-1';
        const walletKeyId2 = 'wallet-key-2';

        // Act
        await store.setMapping(didKeyId, walletKeyId1);
        await store.setMapping(didKeyId, walletKeyId2);
        final retrieved = await store.getWalletKeyId(didKeyId);

        // Assert
        expect(retrieved, walletKeyId2);
      });

      test('should handle removing non-existent mapping', () async {
        // Act & Assert - Should not throw
        expect(() async => await store.removeMapping('non-existent'),
            returnsNormally);
      });
    });

    group('Multiple mappings', () {
      test('should handle multiple different mappings', () async {
        // Arrange
        const mapping1 = ('did:key:abc#key1', 'wallet-1');
        const mapping2 = ('did:key:def#key2', 'wallet-2');
        const mapping3 = ('did:peer:ghi#key3', 'wallet-3');

        // Act
        await store.setMapping(mapping1.$1, mapping1.$2);
        await store.setMapping(mapping2.$1, mapping2.$2);
        await store.setMapping(mapping3.$1, mapping3.$2);

        // Assert
        expect(await store.getWalletKeyId(mapping1.$1), mapping1.$2);
        expect(await store.getWalletKeyId(mapping2.$1), mapping2.$2);
        expect(await store.getWalletKeyId(mapping3.$1), mapping3.$2);
      });

      test('should maintain mappings after removal', () async {
        // Arrange
        await store.setMapping('did:key:1#key', 'wallet-1');
        await store.setMapping('did:key:2#key', 'wallet-2');
        await store.setMapping('did:key:3#key', 'wallet-3');

        // Act
        await store.removeMapping('did:key:2#key');

        // Assert
        expect(await store.getWalletKeyId('did:key:1#key'), 'wallet-1');
        expect(await store.getWalletKeyId('did:key:2#key'), isNull);
        expect(await store.getWalletKeyId('did:key:3#key'), 'wallet-3');
      });

      test('should clear all mappings', () async {
        // Arrange
        await store.setMapping('did:key:1#key', 'wallet-1');
        await store.setMapping('did:key:2#key', 'wallet-2');
        await store.setMapping('did:key:3#key', 'wallet-3');

        // Act
        await store.clearAll();

        // Assert
        expect(await store.getWalletKeyId('did:key:1#key'), isNull);
        expect(await store.getWalletKeyId('did:key:2#key'), isNull);
        expect(await store.getWalletKeyId('did:key:3#key'), isNull);
        expect(await store.verificationMethodIds, isEmpty);
      });
    });

    group('Non-existent keys', () {
      test('should handle empty string key', () async {
        // Act
        await store.setMapping('', 'wallet-empty');
        final retrieved = await store.getWalletKeyId('');

        // Assert
        expect(retrieved, 'wallet-empty');
      });

      test('should handle null values gracefully', () async {
        // Act
        final retrieved = await store.getWalletKeyId('never-set');

        // Assert
        expect(retrieved, isNull);
      });

      test('should handle special characters in keys', () async {
        // Arrange
        const complexDidKeyId = 'did:key:z6Mk...#key-1!@#\$%^&*()_+';
        const walletKeyId = 'wallet-special';

        // Act
        await store.setMapping(complexDidKeyId, walletKeyId);
        final retrieved = await store.getWalletKeyId(complexDidKeyId);

        // Assert
        expect(retrieved, walletKeyId);
      });
    });

    group('verificationMethodIds getter', () {
      test('should return empty list when no mappings', () async {
        // Assert
        expect(await store.verificationMethodIds, isEmpty);
      });

      test('should return all DID key IDs', () async {
        // Arrange
        await store.setMapping('did:key:1#key', 'wallet-1');
        await store.setMapping('did:key:2#key', 'wallet-2');
        await store.setMapping('did:key:3#key', 'wallet-3');

        // Act
        final keys = await store.verificationMethodIds;

        // Assert
        expect(keys.length, 3);
        expect(keys,
            containsAll(['did:key:1#key', 'did:key:2#key', 'did:key:3#key']));
      });

      test('should update after removal', () async {
        // Arrange
        await store.setMapping('did:key:1#key', 'wallet-1');
        await store.setMapping('did:key:2#key', 'wallet-2');

        // Act
        await store.removeMapping('did:key:1#key');
        final keys = await store.verificationMethodIds;

        // Assert
        expect(keys.length, 1);
        expect(keys, contains('did:key:2#key'));
        expect(keys, isNot(contains('did:key:1#key')));
      });

      test('should be empty after clear', () async {
        // Arrange
        await store.setMapping('did:key:1#key', 'wallet-1');
        await store.setMapping('did:key:2#key', 'wallet-2');

        // Act
        await store.clearAll();

        // Assert
        expect(await store.verificationMethodIds, isEmpty);
      });
    });

    group('Edge cases', () {
      test('should handle mapping same wallet key to multiple DID keys',
          () async {
        // Arrange
        const walletKeyId = 'shared-wallet-key';

        // Act
        await store.setMapping('did:key:1#key', walletKeyId);
        await store.setMapping('did:key:2#key', walletKeyId);
        await store.setMapping('did:peer:3#key', walletKeyId);

        // Assert
        expect(await store.getWalletKeyId('did:key:1#key'), walletKeyId);
        expect(await store.getWalletKeyId('did:key:2#key'), walletKeyId);
        expect(await store.getWalletKeyId('did:peer:3#key'), walletKeyId);
      });

      test('should handle very long key identifiers', () async {
        // Arrange
        final longDidKeyId = 'did:key:${'z' * 100}#${'key' * 50}';
        final longWalletKeyId = 'wallet-${'x' * 200}';

        // Act
        await store.setMapping(longDidKeyId, longWalletKeyId);
        final retrieved = await store.getWalletKeyId(longDidKeyId);

        // Assert
        expect(retrieved, longWalletKeyId);
      });

      test('should maintain order of verificationMethodIds', () async {
        // Arrange
        final keys = ['did:key:c#key', 'did:key:a#key', 'did:key:b#key'];

        // Act
        for (final key in keys) {
          await store.setMapping(key, 'wallet-${key.substring(8, 9)}');
        }

        // Assert - Keys should be in insertion order, not alphabetical
        final retrievedKeys = await store.verificationMethodIds;
        expect(retrievedKeys[0], 'did:key:c#key');
        expect(retrievedKeys[1], 'did:key:a#key');
        expect(retrievedKeys[2], 'did:key:b#key');
      });
    });

    group('Custom DidStore implementation example', () {
      test('should work with custom implementation', () async {
        // Example of a custom implementation that could be used
        final customStore = _CustomPersistentStore();

        // Should implement the same interface
        await customStore.setMapping('did:key:test#key', 'wallet-test');
        expect(await customStore.getWalletKeyId('did:key:test#key'),
            'wallet-test');

        await customStore.removeMapping('did:key:test#key');
        expect(await customStore.getWalletKeyId('did:key:test#key'), isNull);

        await customStore.setMapping('did:key:1#key', 'wallet-1');
        await customStore.setMapping('did:key:2#key', 'wallet-2');
        expect((await customStore.verificationMethodIds).length, 2);

        await customStore.clearAll();
        expect(await customStore.verificationMethodIds, isEmpty);
      });
    });
  });
}

// Example custom implementation for testing
class _CustomPersistentStore extends DidStore {
  final Map<String, String> _storage = {};
  final List<String> _authentication = [];
  final List<String> _keyAgreement = [];
  final List<String> _capabilityInvocation = [];
  final List<String> _capabilityDelegation = [];
  final List<String> _assertionMethod = [];
  final List<ServiceEndpoint> _serviceEndpoints = [];

  @override
  Future<void> setMapping(
      String verificationMethodId, String walletKeyId) async {
    _storage[verificationMethodId] = walletKeyId;
    // In a real implementation, this might persist to disk/database
  }

  @override
  Future<String?> getWalletKeyId(String verificationMethodId) async {
    return _storage[verificationMethodId];
  }

  @override
  Future<void> removeMapping(String verificationMethodId) async {
    _storage.remove(verificationMethodId);
  }

  @override
  Future<void> clearAll() async {
    _storage.clear();
    await clearVerificationMethodReferences();
    await clearServiceEndpoints();
  }

  @override
  Future<List<String>> get verificationMethodIds async =>
      _storage.keys.toList();

  @override
  Future<List<String>> get authentication async => _authentication;

  @override
  Future<List<String>> get keyAgreement async => _keyAgreement;

  @override
  Future<List<String>> get capabilityInvocation async => _capabilityInvocation;

  @override
  Future<List<String>> get capabilityDelegation async => _capabilityDelegation;

  @override
  Future<List<String>> get assertionMethod async => _assertionMethod;

  @override
  Future<List<ServiceEndpoint>> get serviceEndpoints async => _serviceEndpoints;

  @override
  Future<void> addAuthentication(String verificationMethodId) async {
    if (!_authentication.contains(verificationMethodId)) {
      _authentication.add(verificationMethodId);
    }
  }

  @override
  Future<void> removeAuthentication(String verificationMethodId) async {
    _authentication.remove(verificationMethodId);
  }

  @override
  Future<void> addKeyAgreement(String verificationMethodId) async {
    if (!_keyAgreement.contains(verificationMethodId)) {
      _keyAgreement.add(verificationMethodId);
    }
  }

  @override
  Future<void> removeKeyAgreement(String verificationMethodId) async {
    _keyAgreement.remove(verificationMethodId);
  }

  @override
  Future<void> addCapabilityInvocation(String verificationMethodId) async {
    if (!_capabilityInvocation.contains(verificationMethodId)) {
      _capabilityInvocation.add(verificationMethodId);
    }
  }

  @override
  Future<void> removeCapabilityInvocation(String verificationMethodId) async {
    _capabilityInvocation.remove(verificationMethodId);
  }

  @override
  Future<void> addCapabilityDelegation(String verificationMethodId) async {
    if (!_capabilityDelegation.contains(verificationMethodId)) {
      _capabilityDelegation.add(verificationMethodId);
    }
  }

  @override
  Future<void> removeCapabilityDelegation(String verificationMethodId) async {
    _capabilityDelegation.remove(verificationMethodId);
  }

  @override
  Future<void> addAssertionMethod(String verificationMethodId) async {
    if (!_assertionMethod.contains(verificationMethodId)) {
      _assertionMethod.add(verificationMethodId);
    }
  }

  @override
  Future<void> removeAssertionMethod(String verificationMethodId) async {
    _assertionMethod.remove(verificationMethodId);
  }

  @override
  Future<void> addServiceEndpoint(ServiceEndpoint endpoint) async {
    if (!_serviceEndpoints.any((se) => se.id == endpoint.id)) {
      _serviceEndpoints.add(endpoint);
    }
  }

  @override
  Future<void> removeServiceEndpoint(String id) async {
    _serviceEndpoints.removeWhere((se) => se.id == id);
  }

  @override
  Future<void> clearVerificationMethodReferences() async {
    _authentication.clear();
    _keyAgreement.clear();
    _capabilityInvocation.clear();
    _capabilityDelegation.clear();
    _assertionMethod.clear();
  }

  @override
  Future<void> clearServiceEndpoints() async {
    _serviceEndpoints.clear();
  }
}
