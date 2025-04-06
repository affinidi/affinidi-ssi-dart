import 'dart:convert';

import 'package:ssi/src/util/base64_util.dart';
import 'package:test/test.dart';

void main() {
  group('Test Encoding No Pad', () {
    test('gbase64UrlEncodeNoPad', () async {
      final endcoded = base64UrlNoPadEncode(utf8.encode('abcd'));
      expect(endcoded, 'YWJjZA');

      final decoded = utf8.decode(base64UrlNoPadDecode(endcoded));
      expect(decoded, 'abcd');
    });
  });
}
