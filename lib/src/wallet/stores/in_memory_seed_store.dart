import 'dart:typed_data';

import 'seed_store_interface.dart';

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
