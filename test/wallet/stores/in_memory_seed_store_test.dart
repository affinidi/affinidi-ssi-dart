import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('InMemorySeedStore', () {
    late InMemorySeedStore seedStore;
    final testSeed = Uint8List.fromList([10, 20, 30, 40, 50]);
    final anotherSeed = Uint8List.fromList([1, 2, 3]);

    setUp(() {
      seedStore = InMemorySeedStore();
    });

    test('getSeed returns null initially', () async {
      expect(await seedStore.getSeed(), isNull);
    });

    test('setSeed and getSeed should store and retrieve the seed', () async {
      await seedStore.setSeed(testSeed);
      final retrievedSeed = await seedStore.getSeed();
      expect(retrievedSeed, isNotNull);
      expect(retrievedSeed, equals(testSeed));
    });

    test('setSeed overwrites existing seed', () async {
      await seedStore.setSeed(testSeed);
      await seedStore.setSeed(anotherSeed);
      expect(await seedStore.getSeed(), equals(anotherSeed));
    });

    test('clear should remove the seed', () async {
      await seedStore.setSeed(testSeed);
      await seedStore.clear();
      expect(await seedStore.getSeed(), isNull);
    });
  });
}
