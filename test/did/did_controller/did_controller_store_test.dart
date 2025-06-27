import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DefaultDiDControllerStore', () {
    late DefaultDiDControllerStore store;

    setUp(() {
      store = DefaultDiDControllerStore();
    });

    group('Map/get/remove operations', () {
      test('should set and get mapping', () {
        // Arrange
        const didKeyId =
            'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
        const walletKeyId = 'wallet-key-123';

        // Act
        store.setMapping(didKeyId, walletKeyId);
        final retrieved = store.getWalletKeyId(didKeyId);

        // Assert
        expect(retrieved, walletKeyId);
      });

      test('should return null for non-existent mapping', () {
        // Act
        final retrieved = store.getWalletKeyId('did:key:unknown#key');

        // Assert
        expect(retrieved, isNull);
      });

      test('should remove mapping', () {
        // Arrange
        const didKeyId = 'did:peer:2.Ez...#key-1';
        const walletKeyId = 'wallet-key-456';
        store.setMapping(didKeyId, walletKeyId);

        // Act
        store.removeMapping(didKeyId);
        final retrieved = store.getWalletKeyId(didKeyId);

        // Assert
        expect(retrieved, isNull);
      });

      test('should overwrite existing mapping', () {
        // Arrange
        const didKeyId = 'did:key:z6Mk...#key';
        const walletKeyId1 = 'wallet-key-1';
        const walletKeyId2 = 'wallet-key-2';

        // Act
        store.setMapping(didKeyId, walletKeyId1);
        store.setMapping(didKeyId, walletKeyId2);
        final retrieved = store.getWalletKeyId(didKeyId);

        // Assert
        expect(retrieved, walletKeyId2);
      });

      test('should handle removing non-existent mapping', () {
        // Act & Assert - Should not throw
        expect(() => store.removeMapping('non-existent'), returnsNormally);
      });
    });

    group('Multiple mappings', () {
      test('should handle multiple different mappings', () {
        // Arrange
        const mapping1 = ('did:key:abc#key1', 'wallet-1');
        const mapping2 = ('did:key:def#key2', 'wallet-2');
        const mapping3 = ('did:peer:ghi#key3', 'wallet-3');

        // Act
        store.setMapping(mapping1.$1, mapping1.$2);
        store.setMapping(mapping2.$1, mapping2.$2);
        store.setMapping(mapping3.$1, mapping3.$2);

        // Assert
        expect(store.getWalletKeyId(mapping1.$1), mapping1.$2);
        expect(store.getWalletKeyId(mapping2.$1), mapping2.$2);
        expect(store.getWalletKeyId(mapping3.$1), mapping3.$2);
      });

      test('should maintain mappings after removal', () {
        // Arrange
        store.setMapping('did:key:1#key', 'wallet-1');
        store.setMapping('did:key:2#key', 'wallet-2');
        store.setMapping('did:key:3#key', 'wallet-3');

        // Act
        store.removeMapping('did:key:2#key');

        // Assert
        expect(store.getWalletKeyId('did:key:1#key'), 'wallet-1');
        expect(store.getWalletKeyId('did:key:2#key'), isNull);
        expect(store.getWalletKeyId('did:key:3#key'), 'wallet-3');
      });

      test('should clear all mappings', () {
        // Arrange
        store.setMapping('did:key:1#key', 'wallet-1');
        store.setMapping('did:key:2#key', 'wallet-2');
        store.setMapping('did:key:3#key', 'wallet-3');

        // Act
        store.clear();

        // Assert
        expect(store.getWalletKeyId('did:key:1#key'), isNull);
        expect(store.getWalletKeyId('did:key:2#key'), isNull);
        expect(store.getWalletKeyId('did:key:3#key'), isNull);
        expect(store.didKeyIds, isEmpty);
      });
    });

    group('Non-existent keys', () {
      test('should handle empty string key', () {
        // Act
        store.setMapping('', 'wallet-empty');
        final retrieved = store.getWalletKeyId('');

        // Assert
        expect(retrieved, 'wallet-empty');
      });

      test('should differentiate between similar keys', () {
        // Arrange
        store.setMapping('did:key:abc#key', 'wallet-1');
        store.setMapping('did:key:abc#key2', 'wallet-2');
        store.setMapping('did:key:abcd#key', 'wallet-3');

        // Assert
        expect(store.getWalletKeyId('did:key:abc#key'), 'wallet-1');
        expect(store.getWalletKeyId('did:key:abc#key2'), 'wallet-2');
        expect(store.getWalletKeyId('did:key:abcd#key'), 'wallet-3');
        expect(store.getWalletKeyId('did:key:abc'), isNull);
      });

      test('should handle special characters in keys', () {
        // Arrange
        const complexDidKeyId =
            'did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.Ez6LSj5uJDee3GCqMNNmqEFGhCTNVX8qTf9xAqtYFfbPgNqbq#key-1';
        const walletKeyId = 'wallet-complex';

        // Act
        store.setMapping(complexDidKeyId, walletKeyId);
        final retrieved = store.getWalletKeyId(complexDidKeyId);

        // Assert
        expect(retrieved, walletKeyId);
      });
    });

    group('didKeyIds getter', () {
      test('should return empty list when no mappings', () {
        // Assert
        expect(store.didKeyIds, isEmpty);
      });

      test('should return all DID key IDs', () {
        // Arrange
        store.setMapping('did:key:1#key', 'wallet-1');
        store.setMapping('did:key:2#key', 'wallet-2');
        store.setMapping('did:key:3#key', 'wallet-3');

        // Act
        final keys = store.didKeyIds;

        // Assert
        expect(keys.length, 3);
        expect(keys,
            containsAll(['did:key:1#key', 'did:key:2#key', 'did:key:3#key']));
      });

      test('should update after removal', () {
        // Arrange
        store.setMapping('did:key:1#key', 'wallet-1');
        store.setMapping('did:key:2#key', 'wallet-2');

        // Act
        store.removeMapping('did:key:1#key');
        final keys = store.didKeyIds;

        // Assert
        expect(keys.length, 1);
        expect(keys, contains('did:key:2#key'));
        expect(keys, isNot(contains('did:key:1#key')));
      });

      test('should be empty after clear', () {
        // Arrange
        store.setMapping('did:key:1#key', 'wallet-1');
        store.setMapping('did:key:2#key', 'wallet-2');

        // Act
        store.clear();

        // Assert
        expect(store.didKeyIds, isEmpty);
      });
    });

    group('Edge cases', () {
      test('should handle mapping same wallet key to multiple DID keys', () {
        // Arrange
        const walletKeyId = 'shared-wallet-key';

        // Act
        store.setMapping('did:key:1#key', walletKeyId);
        store.setMapping('did:key:2#key', walletKeyId);
        store.setMapping('did:peer:3#key', walletKeyId);

        // Assert
        expect(store.getWalletKeyId('did:key:1#key'), walletKeyId);
        expect(store.getWalletKeyId('did:key:2#key'), walletKeyId);
        expect(store.getWalletKeyId('did:peer:3#key'), walletKeyId);
      });

      test('should handle very long key identifiers', () {
        // Arrange
        final longDidKeyId = 'did:key:${'z' * 100}#${'key' * 50}';
        final longWalletKeyId = 'wallet-${'x' * 200}';

        // Act
        store.setMapping(longDidKeyId, longWalletKeyId);
        final retrieved = store.getWalletKeyId(longDidKeyId);

        // Assert
        expect(retrieved, longWalletKeyId);
      });

      test('should maintain order of didKeyIds', () {
        // Arrange
        final keys = ['did:key:c#key', 'did:key:a#key', 'did:key:b#key'];

        // Act
        for (final key in keys) {
          store.setMapping(key, 'wallet-${key.substring(8, 9)}');
        }

        // Assert - Keys should be in insertion order, not alphabetical
        final retrievedKeys = store.didKeyIds;
        expect(retrievedKeys[0], 'did:key:c#key');
        expect(retrievedKeys[1], 'did:key:a#key');
        expect(retrievedKeys[2], 'did:key:b#key');
      });
    });

    group('Custom DiDControllerStore implementation example', () {
      test('should work with custom implementation', () {
        // Example of a custom implementation that could be used
        final customStore = _CustomPersistentStore();

        // Should implement the same interface
        customStore.setMapping('did:key:test#key', 'wallet-test');
        expect(customStore.getWalletKeyId('did:key:test#key'), 'wallet-test');

        customStore.removeMapping('did:key:test#key');
        expect(customStore.getWalletKeyId('did:key:test#key'), isNull);

        customStore.setMapping('did:key:1#key', 'wallet-1');
        customStore.setMapping('did:key:2#key', 'wallet-2');
        expect(customStore.didKeyIds.length, 2);

        customStore.clear();
        expect(customStore.didKeyIds, isEmpty);
      });
    });
  });
}

// Example custom implementation for testing
class _CustomPersistentStore extends DiDControllerStore {
  final Map<String, String> _storage = {};

  @override
  void setMapping(String didKeyId, String walletKeyId) {
    _storage[didKeyId] = walletKeyId;
    // In a real implementation, this might persist to disk/database
  }

  @override
  String? getWalletKeyId(String didKeyId) {
    return _storage[didKeyId];
  }

  @override
  void removeMapping(String didKeyId) {
    _storage.remove(didKeyId);
  }

  @override
  void clear() {
    _storage.clear();
  }

  @override
  List<String> get didKeyIds => _storage.keys.toList();
}
