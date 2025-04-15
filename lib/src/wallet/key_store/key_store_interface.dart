/// An interface for a key-value storage.
abstract class KeyStore {
  /// Stores a value associated with the given key.
  Future<void> set(String key, String value);

  /// Retrieves the value associated with the given key.
  /// Returns null if the key does not exist.
  Future<String?> get(String key);

  /// Removes the value associated with the given key.
  Future<void> remove(String key);

  /// Checks if a key exists in the store.
  Future<bool> contains(String key);

  /// Clears all key-value pairs in the store.
  Future<void> clear();
}
