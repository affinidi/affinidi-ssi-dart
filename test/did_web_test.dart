import 'package:ssi/ssi.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';

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

    test('resolves did:web successfully', () async {
      final did = 'did:web:demo.spruceid.com'; // JWK-based
      // final did = 'did:web:identity.foundation'; // Base58-based
      // final did = ? // publicKeyMultibase-based
      final doc = await DidWeb.resolve(did);

      expect(doc.id, equals(did));
      expect(doc.toJson(), contains('id'));
      expect(doc.toJson(), contains('id'));
      expect(
        doc.context.hasUrlContext(Uri.parse('https://www.w3.org/ns/did/v1')),
        true,
      );
    });

    test('throws SsiException on non-200 response', () async {
      final did = 'did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2';

      expectLater(
        DidWeb.resolve(did),
        throwsA(isA<SsiException>().having(
            (e) => e.code, 'code', SsiExceptionType.invalidDidWeb.code)),
      );
    });
  });
}
