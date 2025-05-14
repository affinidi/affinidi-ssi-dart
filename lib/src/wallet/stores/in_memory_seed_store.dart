import 'dart:typed_data';

import 'seed_store_interface.dart';

/// An in-memory implementation of the [SeedStore] interface.
///
/// This implementation stores all keys and seeds in memory and does not persist them.
/// It is primarily used for testing purposes.
class InMemorySeedStore implements SeedStore {
  Uint8List? _seed;

  @override
  Future<void> setSeed(Uint8List seed) async {
    _seed = seed;
  }

  @override
  Future<Uint8List?> getSeed() async {
    return _seed;
  }

  @override
  Future<void> clear() async {
    _seed = null;
  }
}
