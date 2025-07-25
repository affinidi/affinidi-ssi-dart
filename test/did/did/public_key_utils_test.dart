import 'dart:typed_data';

import 'package:ssi/src/did/public_key_utils.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/key_pair/public_key.dart';
import 'package:ssi/src/types.dart';
import 'package:test/test.dart';

void main() {
  group('Test varint', () {
    test('decode should work', () async {
      _testDecode([0x7F], [0x7F], 1);

      _testDecode([0x8F, 0x01], [0x8F], 2);

      _testDecode([0x80, 0x24], [0x12, 0x00], 2);
      _testDecode([0x81, 0x24], [0x12, 0x01], 2);
      _testDecode([0xED, 0x01], [0xED], 2);
      _testDecode([0xEB, 0x01], [0xEB], 2);
      _testDecode([0x86, 0x24], [0x12, 0x06], 2);

      _testDecode([0x86, 0x24], [0x12, 0x06], 2);

      _testDecode([0xFF, 0xFF, 0x03], [0xFF, 0xFF], 3);
      _testDecode(
        [0x80, 0xFF, 0xFF, 0x80, 0x7F],
        [0x07, 0xF0, 0x1F, 0xFF, 0x80],
        5,
      );
      _testDecode(
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        8,
      );
      _testDecode(
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF],
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        8,
      );
    });

    test('decode should throw exception end of stream', () async {
      (Uint8List, int) shouldThrow() =>
          decodeVarint(Uint8List.fromList([0xFF]));

      expect(
        shouldThrow,
        throwsA(
          isA<SsiException>().having(
            (error) => error.message,
            'message',
            'End reached without complete varint',
          ),
        ),
      );
    });
  });

  group('Test multi-base', () {
    test('base58', () async {
      final input = Uint8List.fromList([1, 2, 3]);

      final encoded = toMultiBase(input);
      final decoded = multiBaseToUint8List(encoded);

      expect(decoded, input);
    });

    test('base64', () async {
      final input = Uint8List.fromList([1, 2, 3]);

      final encoded = toMultiBase(input, base: MultiBase.base64UrlNoPad);
      final decoded = multiBaseToUint8List(encoded);

      expect(decoded, input);
    });
  });

  group('Test keyToJwk', () {
    test('should convert Ed25519 public key to JWK', () {
      final publicKey = PublicKey(
        'test-key',
        Uint8List.fromList([
          0x11,
          0x22,
          0x33,
          0x44,
          0x55,
          0x66,
          0x77,
          0x88,
          0x99,
          0xaa,
          0xbb,
          0xcc,
          0xdd,
          0xee,
          0xff,
          0x00,
          0x11,
          0x22,
          0x33,
          0x44,
          0x55,
          0x66,
          0x77,
          0x88,
          0x99,
          0xaa,
          0xbb,
          0xcc,
          0xdd,
          0xee,
          0xff,
          0x00
        ]),
        KeyType.ed25519,
      );

      final jwk = keyToJwk(publicKey);

      expect(jwk['kty'], 'OKP');
      expect(jwk['crv'], 'Ed25519');
      expect(jwk['x'], isA<String>());
      expect(jwk.containsKey('y'), false); // Ed25519 doesn't have y coordinate
    });

    test('should convert X25519 public key to JWK', () {
      final publicKey = PublicKey(
        'test-key',
        Uint8List.fromList([
          0x11,
          0x22,
          0x33,
          0x44,
          0x55,
          0x66,
          0x77,
          0x88,
          0x99,
          0xaa,
          0xbb,
          0xcc,
          0xdd,
          0xee,
          0xff,
          0x00,
          0x11,
          0x22,
          0x33,
          0x44,
          0x55,
          0x66,
          0x77,
          0x88,
          0x99,
          0xaa,
          0xbb,
          0xcc,
          0xdd,
          0xee,
          0xff,
          0x00
        ]),
        KeyType.x25519,
      );

      final jwk = keyToJwk(publicKey);

      expect(jwk['kty'], 'OKP');
      expect(jwk['crv'], 'X25519');
      expect(jwk['x'], isA<String>());
      expect(jwk.containsKey('y'), false); // X25519 doesn't have y coordinate
    });

    test('should convert secp256k1 public key to JWK with X and Y coordinates',
        () {
      // Use the known-good secp256k1 multikey from did_document_test.dart
      final multibase = 'zQ3shvpfWjYk7DfbsyAEFQTfmz3qjeDmdNcJ8a1mhkps4qKGj';
      final multikey = multiBaseToUint8List(multibase);
      final keyBytes = multikey.sublist(2); // Remove the 2-byte indicator

      final publicKey = PublicKey(
        'test-key',
        keyBytes,
        KeyType.secp256k1,
      );

      final jwk = keyToJwk(publicKey);

      expect(jwk['kty'], 'EC');
      expect(jwk['crv'], 'secp256k1');
      expect(jwk['x'], isA<String>());
      expect(jwk['y'], isA<String>());
      expect(jwk['x']!.isNotEmpty, true);
      expect(jwk['y']!.isNotEmpty, true);

      // Verify the exact values match the expected ones from did_document_test.dart
      expect(jwk['x'], '8G9rBdSs9mib1X_2K4ify7wFDLT4ZhoVD7aCy-jimUg');
      expect(jwk['y'], '4D9aPYTmYa68Xw3OeFuFE33-l4JrSpQ8Bh4VkBdXvT8');
    });

    test('should throw exception for unsupported key type', () {
      final publicKey = PublicKey(
        'test-key',
        Uint8List.fromList([0x11, 0x22, 0x33]),
        KeyType.rsa, // RSA not supported by toMultikey
      );

      expect(
        () => keyToJwk(publicKey),
        throwsA(
          isA<SsiException>().having(
            (error) => error.message,
            'message',
            contains('not supported'),
          ),
        ),
      );
    });

    test('should verify multiKeyToJwk exposes X and Y properties for EC curves',
        () {
      // Test the underlying multiKeyToJwk function directly with known-good data
      final multibase = 'zQ3shvpfWjYk7DfbsyAEFQTfmz3qjeDmdNcJ8a1mhkps4qKGj';
      final multikey = multiBaseToUint8List(multibase);

      final jwk = multiKeyToJwk(multikey);

      // Verify X and Y coordinates are present and accessible
      expect(jwk, containsPair('x', isA<String>()));
      expect(jwk, containsPair('y', isA<String>()));

      // Verify coordinates are base64url encoded (no padding, URL-safe chars)
      final xCoord = jwk['x'] as String;
      final yCoord = jwk['y'] as String;
      expect(xCoord, matches(r'^[A-Za-z0-9_-]+$')); // base64url pattern
      expect(yCoord, matches(r'^[A-Za-z0-9_-]+$')); // base64url pattern
      expect(xCoord.contains('='), false); // no padding
      expect(yCoord.contains('='), false); // no padding

      // Verify the exact values
      expect(xCoord, '8G9rBdSs9mib1X_2K4ify7wFDLT4ZhoVD7aCy-jimUg');
      expect(yCoord, '4D9aPYTmYa68Xw3OeFuFE33-l4JrSpQ8Bh4VkBdXvT8');
    });
  });
}

void _testDecode(List<int> varint, List<int> expected, int expectedLen) {
  var (decoded, len) = decodeVarint(Uint8List.fromList(varint));
  expect(decoded, expected);
  expect(len, expectedLen);
}
