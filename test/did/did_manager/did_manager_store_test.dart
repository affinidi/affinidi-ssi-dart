import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('InMemoryDidStore', () {
    late InMemoryDidKeyMappingStore keyMappingStore;

    setUp(() {
      keyMappingStore = InMemoryDidKeyMappingStore();
    });

    group('Map/get/remove operations', () {
      test('should set and get mapping', () async {
        // Arrange
        const didKeyId =
            'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
        const walletKeyId = 'wallet-key-123';

        // Act
        await keyMappingStore.setMapping(didKeyId, walletKeyId);
        final retrieved = await keyMappingStore.getWalletKeyId(didKeyId);

        // Assert
        expect(retrieved, walletKeyId);
      });

      test('should return null for non-existent mapping', () async {
        // Act
        final retrieved =
            await keyMappingStore.getWalletKeyId('did:key:unknown#key');

        // Assert
        expect(retrieved, isNull);
      });

      test('should remove mapping', () async {
        // Arrange
        const didKeyId = 'did:peer:2.Ez...#key-1';
        const walletKeyId = 'wallet-key-456';
        await keyMappingStore.setMapping(didKeyId, walletKeyId);

        // Act
        await keyMappingStore.removeMapping(didKeyId);
        final retrieved = await keyMappingStore.getWalletKeyId(didKeyId);

        // Assert
        expect(retrieved, isNull);
      });

      test('should overwrite existing mapping', () async {
        // Arrange
        const didKeyId = 'did:key:z6Mk...#key';
        const walletKeyId1 = 'wallet-key-1';
        const walletKeyId2 = 'wallet-key-2';

        // Act
        await keyMappingStore.setMapping(didKeyId, walletKeyId1);
        await keyMappingStore.setMapping(didKeyId, walletKeyId2);
        final retrieved = await keyMappingStore.getWalletKeyId(didKeyId);

        // Assert
        expect(retrieved, walletKeyId2);
      });

      test('should handle removing non-existent mapping', () async {
        // Act & Assert - Should not throw
        expect(() async => await keyMappingStore.removeMapping('non-existent'),
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
        await keyMappingStore.setMapping(mapping1.$1, mapping1.$2);
        await keyMappingStore.setMapping(mapping2.$1, mapping2.$2);
        await keyMappingStore.setMapping(mapping3.$1, mapping3.$2);

        // Assert
        expect(await keyMappingStore.getWalletKeyId(mapping1.$1), mapping1.$2);
        expect(await keyMappingStore.getWalletKeyId(mapping2.$1), mapping2.$2);
        expect(await keyMappingStore.getWalletKeyId(mapping3.$1), mapping3.$2);
      });

      test('should maintain mappings after removal', () async {
        // Arrange
        await keyMappingStore.setMapping('did:key:1#key', 'wallet-1');
        await keyMappingStore.setMapping('did:key:2#key', 'wallet-2');
        await keyMappingStore.setMapping('did:key:3#key', 'wallet-3');

        // Act
        await keyMappingStore.removeMapping('did:key:2#key');

        // Assert
        expect(
            await keyMappingStore.getWalletKeyId('did:key:1#key'), 'wallet-1');
        expect(await keyMappingStore.getWalletKeyId('did:key:2#key'), isNull);
        expect(
            await keyMappingStore.getWalletKeyId('did:key:3#key'), 'wallet-3');
      });

      test('should clear all mappings', () async {
        // Arrange
        await keyMappingStore.setMapping('did:key:1#key', 'wallet-1');
        await keyMappingStore.setMapping('did:key:2#key', 'wallet-2');
        await keyMappingStore.setMapping('did:key:3#key', 'wallet-3');

        // Act
        await keyMappingStore.clearAll();

        // Assert
        expect(await keyMappingStore.getWalletKeyId('did:key:1#key'), isNull);
        expect(await keyMappingStore.getWalletKeyId('did:key:2#key'), isNull);
        expect(await keyMappingStore.getWalletKeyId('did:key:3#key'), isNull);
        expect(await keyMappingStore.verificationMethodIds, isEmpty);
      });
    });

    group('Non-existent keys', () {
      test('should handle empty string key', () async {
        // Act
        await keyMappingStore.setMapping('', 'wallet-empty');
        final retrieved = await keyMappingStore.getWalletKeyId('');

        // Assert
        expect(retrieved, 'wallet-empty');
      });

      test('should handle null values gracefully', () async {
        // Act
        final retrieved = await keyMappingStore.getWalletKeyId('never-set');

        // Assert
        expect(retrieved, isNull);
      });

      test('should handle special characters in keys', () async {
        // Arrange
        const complexDidKeyId = 'did:key:z6Mk...#key-1!@#\$%^&*()_+';
        const walletKeyId = 'wallet-special';

        // Act
        await keyMappingStore.setMapping(complexDidKeyId, walletKeyId);
        final retrieved = await keyMappingStore.getWalletKeyId(complexDidKeyId);

        // Assert
        expect(retrieved, walletKeyId);
      });
    });

    group('verificationMethodIds getter', () {
      test('should return empty list when no mappings', () async {
        // Assert
        expect(await keyMappingStore.verificationMethodIds, isEmpty);
      });

      test('should return all DID key IDs', () async {
        // Arrange
        await keyMappingStore.setMapping('did:key:1#key', 'wallet-1');
        await keyMappingStore.setMapping('did:key:2#key', 'wallet-2');
        await keyMappingStore.setMapping('did:key:3#key', 'wallet-3');

        // Act
        final keys = await keyMappingStore.verificationMethodIds;

        // Assert
        expect(keys.length, 3);
        expect(keys,
            containsAll(['did:key:1#key', 'did:key:2#key', 'did:key:3#key']));
      });

      test('should update after removal', () async {
        // Arrange
        await keyMappingStore.setMapping('did:key:1#key', 'wallet-1');
        await keyMappingStore.setMapping('did:key:2#key', 'wallet-2');

        // Act
        await keyMappingStore.removeMapping('did:key:1#key');
        final keys = await keyMappingStore.verificationMethodIds;

        // Assert
        expect(keys.length, 1);
        expect(keys, contains('did:key:2#key'));
        expect(keys, isNot(contains('did:key:1#key')));
      });

      test('should be empty after clear', () async {
        // Arrange
        await keyMappingStore.setMapping('did:key:1#key', 'wallet-1');
        await keyMappingStore.setMapping('did:key:2#key', 'wallet-2');

        // Act
        await keyMappingStore.clearAll();

        // Assert
        expect(await keyMappingStore.verificationMethodIds, isEmpty);
      });
    });

    group('Edge cases', () {
      test('should handle mapping same wallet key to multiple DID keys',
          () async {
        // Arrange
        const walletKeyId = 'shared-wallet-key';

        // Act
        await keyMappingStore.setMapping('did:key:1#key', walletKeyId);
        await keyMappingStore.setMapping('did:key:2#key', walletKeyId);
        await keyMappingStore.setMapping('did:peer:3#key', walletKeyId);

        // Assert
        expect(
            await keyMappingStore.getWalletKeyId('did:key:1#key'), walletKeyId);
        expect(
            await keyMappingStore.getWalletKeyId('did:key:2#key'), walletKeyId);
        expect(await keyMappingStore.getWalletKeyId('did:peer:3#key'),
            walletKeyId);
      });

      test('should handle very long key identifiers', () async {
        // Arrange
        final longDidKeyId = 'did:key:${'z' * 100}#${'key' * 50}';
        final longWalletKeyId = 'wallet-${'x' * 200}';

        // Act
        await keyMappingStore.setMapping(longDidKeyId, longWalletKeyId);
        final retrieved = await keyMappingStore.getWalletKeyId(longDidKeyId);

        // Assert
        expect(retrieved, longWalletKeyId);
      });

      test('should maintain order of verificationMethodIds', () async {
        // Arrange
        final keys = ['did:key:c#key', 'did:key:a#key', 'did:key:b#key'];

        // Act
        for (final key in keys) {
          await keyMappingStore.setMapping(
              key, 'wallet-${key.substring(8, 9)}');
        }

        // Assert - Keys should be in insertion order, not alphabetical
        final retrievedKeys = await keyMappingStore.verificationMethodIds;
        expect(retrievedKeys[0], 'did:key:c#key');
        expect(retrievedKeys[1], 'did:key:a#key');
        expect(retrievedKeys[2], 'did:key:b#key');
      });
    });

    group('Custom DidStore implementation example', () {
      test('should work with custom implementation', () async {
        // Example of a custom implementation that could be used
        final customStore = InMemoryDidKeyMappingStore();

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
