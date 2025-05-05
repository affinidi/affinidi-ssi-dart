import 'dart:typed_data';

/// An interface for a key-value storage.
abstract class SeedStore {
  /// Stores the seed value, overwriting any previous seed.
  Future<void> setSeed(Uint8List seed);

  /// Retrieves the stored seed value.
  /// Returns null if no seed has been stored.
  Future<Uint8List?> getSeed();

  /// Clears the stored seed.
  Future<void> clear();
}
