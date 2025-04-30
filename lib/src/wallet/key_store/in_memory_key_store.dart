import 'dart:typed_data';

import 'key_store_interface.dart';
import 'stored_key.dart';

/// In memory key store used for testing
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
