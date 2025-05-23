import 'dart:convert';

import 'package:ssi/src/did/universal_did_resolver.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';
import 'package:test/test.dart';

import '../fixtures/did_document_fixtures.dart';

void main() {
  group('When resolving did document', () {
    group('using did:key,', () {
      test('it resolves succesfully', () async {
        final did = 'did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R';

        final expectedDidDoc =
            jsonDecode(DidDocumentFixtures.didDocumentWithControllerKey);

        final resolvedDidDocument = await UniversalDIDResolver.resolve(did);
        expect(resolvedDidDocument.toJson(), expectedDidDoc);
      });
    });

    group('using did:peer,', () {
      test('it resolves successfully', () async {
        final did =
            'did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka';

        final expectedDidDoc =
            jsonDecode(DidDocumentFixtures.didDocumentWithControllerPeer);

        final resolvedDidDoc = await UniversalDIDResolver.resolve(did);

        expect(resolvedDidDoc.toJson(), expectedDidDoc);
      });
    });

    group('using did:web,', () {
      test('it throws exception on non-200 responces', () {
        final did = 'did:web:example.com';

        expectLater(
          UniversalDIDResolver.resolve(did),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.invalidDidWeb.code)),
        );
      });
    });

    group('using resolver address', () {
      test('it throws undable to resolve did when resolverAddress null', () {
        final did = 'did:test';

        expectLater(
          UniversalDIDResolver.resolve(did),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.unableToResolveDid.code)),
        );
      });

      test('it throws exception on non-200 responces', () {
        final did = 'did:test';
        final resolverAddress = 'https://example.com';

        expectLater(
          UniversalDIDResolver.resolve(did, resolverAddress: resolverAddress),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.unableToResolveDid.code)),
        );
      });
    });
  });
}
