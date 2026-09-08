import 'dart:convert';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('When parsing malformed JWT input', () {
    final suite = JwtDm1Suite();
    final invalidEncoding = isA<SsiException>().having(
      (error) => error.code,
      'code',
      SsiExceptionType.invalidEncoding.code,
    );

    test('it rejects invalid base64url with a typed exception', () {
      expect(() => suite.parse('!!!.e30.signature'), throwsA(invalidEncoding));
    });

    test('it rejects a header that is not a JSON object', () {
      final arrayHeader = base64Url.encode(utf8.encode('[]'));

      expect(
        () => suite.parse('$arrayHeader.e30.signature'),
        throwsA(invalidEncoding),
      );
    });

    test('it rejects a payload that is not a JSON object', () {
      final arrayPayload = base64Url.encode(utf8.encode('[]'));

      expect(
        () => suite.parse('e30.$arrayPayload.signature'),
        throwsA(invalidEncoding),
      );
    });
  });
}
