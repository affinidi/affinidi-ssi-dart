import 'dart:typed_data';

import 'key_store_interface.dart';
import 'stored_key.dart';

/// An in-memory implementation of the [KeyStore] interface.
///
/// This implementation stores all keys and seeds in memory and does not persist them.
/// It is primarily used for testing purposes.
class InMemoryKeyStore implements KeyStore {
  final Map<String, StoredKey> _keyPairStore = {};
  Uint8List? _seed;

  @override
  Future<void> set(String key, StoredKey value) async {
    _keyPairStore[key] = value;
  }

  @override
  Future<StoredKey?> get(String key) async {
    return _keyPairStore[key];
  }

  @override
  Future<void> setSeed(Uint8List seed) async {
    _seed = seed;
  }

  @override
  Future<Uint8List?> getSeed() async {
    return _seed;
  }

  @override
  Future<void> remove(String key) async {
    _keyPairStore.remove(key);
  }

  @override
  Future<bool> contains(String key) async {
    return _keyPairStore.containsKey(key);
  }

  @override
  Future<void> clear() async {
    _keyPairStore.clear();
    _seed = null;
  }
}
