import 'dart:typed_data';

import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('InMemoryKeyStore', () {
    late InMemoryKeyStore keyStore;
    const testKeyId = 'test-key';
    final testStoredKey = StoredKey(
      type: KeyType.p256,
      key: Uint8List.fromList([1, 2, 3]),
    );
    final testSeed = Uint8List.fromList([10, 20, 30]);

    setUp(() {
      keyStore = InMemoryKeyStore();
    });

    test('set and get should store and retrieve a key', () async {
      expect(await keyStore.get(testKeyId), isNull);
      await keyStore.set(testKeyId, testStoredKey);
      final retrievedKey = await keyStore.get(testKeyId);
      expect(retrievedKey, isNotNull);
      expect(retrievedKey!.type, testStoredKey.type);
      expect(retrievedKey.key, testStoredKey.key);
    });

    test('setSeed and getSeed should store and retrieve the seed', () async {
      expect(await keyStore.getSeed(), isNull);
      await keyStore.setSeed(testSeed);
      final retrievedSeed = await keyStore.getSeed();
      expect(retrievedSeed, isNotNull);
      expect(retrievedSeed, equals(testSeed));
    });

    test('contains should return true for existing key, false otherwise',
        () async {
      expect(await keyStore.contains(testKeyId), isFalse);
      await keyStore.set(testKeyId, testStoredKey);
      expect(await keyStore.contains(testKeyId), isTrue);
    });

    test('remove should delete the key', () async {
      await keyStore.set(testKeyId, testStoredKey);
      expect(await keyStore.contains(testKeyId), isTrue);
      await keyStore.remove(testKeyId);
      expect(await keyStore.contains(testKeyId), isFalse);
      expect(await keyStore.get(testKeyId), isNull);
    });

    test('clear should remove all keys and the seed', () async {
      await keyStore.set(testKeyId, testStoredKey);
      await keyStore.setSeed(testSeed);

      expect(await keyStore.contains(testKeyId), isTrue);
      expect(await keyStore.getSeed(), isNotNull);

      await keyStore.clear();

      expect(await keyStore.contains(testKeyId), isFalse);
      expect(await keyStore.get(testKeyId), isNull);
      expect(await keyStore.getSeed(), isNull);
    });
  });
}
