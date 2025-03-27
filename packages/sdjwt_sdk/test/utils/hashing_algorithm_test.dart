import 'package:sdjwt_sdk/src/base/hasher.dart';
import 'package:test/test.dart';

void main() {
  group('HashingAlgorithm Tests', () {
    test('fromString returns correct algorithm', () {
      expect(Hasher.fromString('sha-256'), equals(Hasher.sha256));
      expect(Hasher.fromString('sha-384'), equals(Hasher.sha384));
      expect(Hasher.fromString('sha-512'), equals(Hasher.sha512));
      expect(Hasher.fromString('sha-512-256'), equals(Hasher.sha512_256));
    });

    test('fromString returns sha256 for invalid algorithm name', () {
      expect(Hasher.fromString('invalid'), equals(Hasher.sha256));
    });

    test('convert produces different hashes for different algorithms', () {
      const testInput = 'test input string';
      final sha256Hash = Hasher.sha256.execute(testInput);
      final sha384Hash = Hasher.sha384.execute(testInput);
      final sha512Hash = Hasher.sha512.execute(testInput);

      expect(sha256Hash, hasLength(32)); // SHA-256 produces 32 bytes
      expect(sha384Hash, hasLength(48)); // SHA-384 produces 48 bytes
      expect(sha512Hash, hasLength(64)); // SHA-512 produces 64 bytes

      expect(sha256Hash, isNot(equals(sha384Hash)));
      expect(sha384Hash, isNot(equals(sha512Hash)));
      expect(sha512Hash, isNot(equals(sha256Hash)));
    });

    test('same input produces same hash', () {
      const input = 'test input string';
      for (final algorithm in Hasher.bundledHashers) {
        final hash1 = algorithm.execute(input);
        final hash2 = algorithm.execute(input);
        expect(hash1, equals(hash2));
      }
    });
  });
}
