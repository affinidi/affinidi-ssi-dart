import 'dart:convert';

import 'package:ssi/src/did/did_resolver.dart';
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

        final resolvedDidDocument =
            await UniversalDIDResolver.defaultResolver.resolveDid(did);
        expect(resolvedDidDocument.toJson(), expectedDidDoc);
      });
    });

    group('using did:peer,', () {
      test('it resolves successfully', () async {
        final did =
            'did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka';

        final expectedDidDoc =
            jsonDecode(DidDocumentFixtures.didDocumentWithControllerPeer);

        final resolvedDidDoc =
            await UniversalDIDResolver.defaultResolver.resolveDid(did);

        expect(resolvedDidDoc.toJson(), expectedDidDoc);
      });
    });

    group('using did:web,', () {
      test('it throws exception on non-200 responces', () {
        final did = 'did:web:example.com';

        expectLater(
          UniversalDIDResolver.defaultResolver.resolveDid(did),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.invalidDidWeb.code)),
        );
      });
    });

    group('using resolver address', () {
      test('it throws undable to resolve did when resolverAddress null', () {
        final did = 'did:test';

        expectLater(
          UniversalDIDResolver.defaultResolver.resolveDid(did),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.unableToResolveDid.code)),
        );
      });

      test('it throws exception on non-200 responces', () async {
        final did = 'did:test';
        final resolverAddress = 'https://example.com';
        final resolver = UniversalDIDResolver(resolverAddress: resolverAddress);

        await expectLater(
          resolver.resolveDid(did),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.unableToResolveDid.code)),
        );
      });
    });
  });

  group('DidResolver interface', () {
    test('defaultResolver should implement DidResolver interface', () {
      expect(UniversalDIDResolver.defaultResolver, isA<DidResolver>());
    });

    test('defaultResolver should resolve DIDs using instance method', () async {
      final did = 'did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R';
      final expectedDidDoc =
          jsonDecode(DidDocumentFixtures.didDocumentWithControllerKey);

      final resolvedDidDocument =
          await UniversalDIDResolver.defaultResolver.resolveDid(did);
      expect(resolvedDidDocument.toJson(), expectedDidDoc);
    });

    test('instance with resolverAddress should handle external DIDs', () async {
      final did = 'did:test';
      final resolverAddress = 'https://example.com';
      final resolver = UniversalDIDResolver(resolverAddress: resolverAddress);

      await expectLater(
        resolver.resolveDid(did),
        throwsA(isA<SsiException>().having(
            (e) => e.code, 'code', SsiExceptionType.unableToResolveDid.code)),
      );
    });

    test('defaultResolver maintains backward compatibility', () async {
      final did = 'did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R';
      final expectedDidDoc =
          jsonDecode(DidDocumentFixtures.didDocumentWithControllerKey);

      final resolvedDidDocument =
          await UniversalDIDResolver.defaultResolver.resolveDid(did);
      expect(resolvedDidDocument.toJson(), expectedDidDoc);
    });

    test('defaultResolver can be used directly', () async {
      final did = 'did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R';
      final expectedDidDoc =
          jsonDecode(DidDocumentFixtures.didDocumentWithControllerKey);

      final resolvedDidDocument =
          await UniversalDIDResolver.defaultResolver.resolveDid(did);
      expect(resolvedDidDocument.toJson(), expectedDidDoc);
    });
  });
}
