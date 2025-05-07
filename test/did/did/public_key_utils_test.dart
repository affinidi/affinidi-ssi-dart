import 'dart:typed_data';

import 'package:ssi/src/did/public_key_utils.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
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
}

void _testDecode(List<int> varint, List<int> expected, int expectedLen) {
  var (decoded, len) = decodeVarint(Uint8List.fromList(varint));
  expect(decoded, expected);
  expect(len, expectedLen);
}
