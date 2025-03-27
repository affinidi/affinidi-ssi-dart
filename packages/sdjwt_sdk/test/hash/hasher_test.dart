import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:sdjwt_sdk/src/base/hasher.dart';
import 'package:test/test.dart';

void main() {
  group('Hasher Implementations', () {
    test('SHA256 should return correct hash', () {
      const hasher = Hasher.sha256;
      final input = 'Rain Bow';
      final expectedHash =
          Uint8List.fromList(sha256.convert(utf8.encode(input)).bytes);
      final result = hasher.execute(input);
      expect(result, equals(expectedHash));
    });

    test('SHA384 should return correct hash', () {
      const hasher = Hasher.sha384;
      final input = 'Rain Bow';
      final expectedHash =
          Uint8List.fromList(sha384.convert(utf8.encode(input)).bytes);

      final result = hasher.execute(input);

      expect(result, equals(expectedHash));
    });

    test('SHA512 should return correct hash', () {
      const hasher = Hasher.sha512;
      final input = 'Rain Bow';
      final expectedHash =
          Uint8List.fromList(sha512.convert(utf8.encode(input)).bytes);

      final result = hasher.execute(input);

      expect(result, equals(expectedHash));
    });

    test('SHA512_256 should return correct hash', () {
      const hasher = Hasher.sha512_256;
      final input = 'Rain Bow';
      final expectedHash =
          Uint8List.fromList(sha512256.convert(utf8.encode(input)).bytes);

      final result = hasher.execute(input);

      expect(result, equals(expectedHash));
    });
  });

  group('Base64EncodedOutputHasher', () {
    test(
        'Base64EncodedOutputHasher.base64Sha256 should return base64 encoded hash without padding',
        () {
      const input = 'Rain Bow';
      const expectedEncoded = '7uuXgpX2IsJZXnfP6rOFpgfKJPu78KR8deBxJyt4EtY';
      final result = Base64EncodedOutputHasher.base64Sha256.execute(input);
      expect(result, equals(expectedEncoded));
    });

    test('Base64EncodedOutputHasher should use correct underlying hasher name',
        () {
      const underlyingHasher = Hasher.sha512;
      final hasher = Base64EncodedOutputHasher(Hasher.sha512);
      expect(hasher.name, equals(underlyingHasher.name));
    });
  });
}
