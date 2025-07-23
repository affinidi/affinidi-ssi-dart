import 'package:ssi/ssi.dart';

import 'package:test/test.dart';

void main() {
  group('Test DidWeb', () {
    test('converts did:web:example.com to expected URI', () {
      final uri = didWebToUri('did:web:example.com');
      expect(uri.toString(), 'https://example.com/.well-known/did.json');
    });

    test('converts nested did:web:example.com:user to correct URI', () {
      final uri = didWebToUri('did:web:example.com:user');
      expect(uri.toString(), 'https://example.com/user/did.json');
    });

    test('throws SsiException on non-200 response', () async {
      final did = 'did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2';

      await expectLater(
        DidWeb.resolve(did),
        throwsA(isA<SsiException>().having(
            (e) => e.code, 'code', SsiExceptionType.invalidDidWeb.code)),
      );
    });
  });
}
