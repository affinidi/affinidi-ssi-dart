import 'dart:typed_data';

import 'package:ssi/src/wallet/stores/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('InMemoryKeyStore', () {
    late InMemoryKeyStore keyStore;
    const testKeyId = 'test-key';
    final testStoredKey = StoredKey(
        keyType: KeyType.p256, privateKeyBytes: Uint8List.fromList([1, 2, 3]));

    setUp(() {
      keyStore = InMemoryKeyStore();
    });

    test('set and get should store and retrieve a key', () async {
      expect(await keyStore.get(testKeyId), isNull);
      await keyStore.set(testKeyId, testStoredKey);
      final retrievedKey = await keyStore.get(testKeyId);
      expect(retrievedKey, isNotNull);
      expect(retrievedKey!.keyType, testStoredKey.keyType);
      expect(retrievedKey.privateKeyBytes, testStoredKey.privateKeyBytes);
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

    test('clear should remove all keys', () async {
      await keyStore.set(testKeyId, testStoredKey);

      expect(await keyStore.contains(testKeyId), isTrue);

      await keyStore.clear();

      expect(await keyStore.contains(testKeyId), isFalse);
      expect(await keyStore.get(testKeyId), isNull);
    });
  });
}
