import 'dart:typed_data';

import 'stored_key.dart';

/// An interface for a key-value storage.
abstract class KeyStore {
  /// Stores a value associated with the given key.
  Future<void> set(String key, StoredKey value);

  /// Retrieves the value associated with the given key.
  /// Returns null if the key does not exist or stores a seed.
  Future<StoredKey?> get(String key);

  /// Stores the seed value, overwriting any previous seed.
  Future<void> setSeed(Uint8List seed);

  /// Retrieves the stored seed value.
  /// Returns null if no seed has been stored.
  Future<Uint8List?> getSeed();

  /// Removes the key pair associated with the given key. Does not affect the seed.
  Future<void> remove(String key);

  /// Checks if a key pair (not a seed) exists in the store for the given key.
  Future<bool> contains(String key);

  /// Clears all stored key pairs and the single seed.
  Future<void> clear();
}
