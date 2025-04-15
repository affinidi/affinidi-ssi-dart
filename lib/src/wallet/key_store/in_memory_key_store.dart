import 'key_store_interface.dart';

class InMemoryKeyStore implements KeyStore {
  final Map<String, String> _store = {};

  @override
  Future<void> set(String key, String value) async {
    _store[key] = value;
  }

  @override
  Future<String?> get(String key) async {
    return _store[key];
  }

  @override
  Future<void> remove(String key) async {
    _store.remove(key);
  }

  @override
  Future<bool> contains(String key) async {
    return _store.containsKey(key);
  }

  @override
  Future<void> clear() async {
    _store.clear();
  }
}
