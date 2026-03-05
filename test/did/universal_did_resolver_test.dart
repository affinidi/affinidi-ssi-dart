// ignore_for_file: avoid_print

import 'dart:convert';

import 'package:ssi/src/did/did_resolver.dart';
import 'package:ssi/src/did/universal_did_resolver.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../fixtures/did_document_fixtures.dart';

void main() {
  group('When resolving did document', () {
    group('using did:key,', () {
      test('it resolves successfully', () async {
        final did = 'did:key:zQ3shZpqW9nCcCo9Lz74rG4vYXra1fVDYCzyomC2zNZhaDa7R';

        final expectedDidDoc =
            jsonDecode(DidDocumentFixtures.didDocumentWithControllerKey);

        final resolvedDidDocument =
            await UniversalDIDResolver.defaultResolver.resolveDid(did);
        expect(resolvedDidDocument.toJson(), expectedDidDoc);
      });
    });

    group('using did:webvh', () {
      test('it resolves successfully', () async {
        final String expectedDidDocAsString = '''
{
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1"
    ],
    "id": "did:webvh:QmRcnRLQ5GGA3JUtCMyEdMEkssSg8Hkvjj9EfKaRQw4YbZ:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob",
    "alsoKnownAs": [
        "did:web:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob"
    ],
    "verificationMethod": [
        {
            "id": "did:webvh:QmRcnRLQ5GGA3JUtCMyEdMEkssSg8Hkvjj9EfKaRQw4YbZ:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob#auth-1",
            "type": "Multikey",
            "controller": "did:webvh:QmRcnRLQ5GGA3JUtCMyEdMEkssSg8Hkvjj9EfKaRQw4YbZ:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob",
            "publicKeyMultibase": "z6MkqjUwiNU7cpVoAznWiNg3XT8GNbEHbzf5yqCq8rYFvVYm"
        }
    ],
    "authentication": [
        "did:webvh:QmRcnRLQ5GGA3JUtCMyEdMEkssSg8Hkvjj9EfKaRQw4YbZ:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob#auth-1"
    ],
    "assertionMethod": [
        "did:webvh:QmRcnRLQ5GGA3JUtCMyEdMEkssSg8Hkvjj9EfKaRQw4YbZ:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob#auth-1"
    ],
    "service": [
        {
            "id": "#whois",
            "type": "LinkedVerifiablePresentation",
            "serviceEndpoint": "https://raw.githubusercontent.com/affinidi/affinidi-ssi-dart/refs/heads/main/example/dids/didwebvh/bob/whois.vp"
        },
        {
            "id": "#files",
            "type": "relativeRef",
            "serviceEndpoint": "https://raw.githubusercontent.com/affinidi/affinidi-ssi-dart/refs/heads/main/example/dids/didwebvh/bob"
        }
    ]
}
''';
        final did =
            'did:webvh:QmRcnRLQ5GGA3JUtCMyEdMEkssSg8Hkvjj9EfKaRQw4YbZ:raw.githubusercontent.com:affinidi:affinidi-ssi-dart:refs:heads:main:example:dids:didwebvh:bob';

        final expectedDidDocCanon =
            JcsUtil.canonicalize(jsonDecode(expectedDidDocAsString));

        final resolvedDidDoc =
            await UniversalDIDResolver.defaultResolver.resolveDid(did);
        final resolvedDidDocCanon =
            JcsUtil.canonicalize(resolvedDidDoc.toJson());

        expect(resolvedDidDocCanon, expectedDidDocCanon);
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
      test('it throws exception on non-200 responses', () async {
        // Use non-routable address to fail immediately instead of timing out
        final did = 'did:web:0.0.0.0%3A1';

        await expectLater(
          UniversalDIDResolver.defaultResolver.resolveDid(did),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.invalidDidWeb.code)),
        );
      });
    });

    group('using resolver address', () {
      test('it throws unable to resolve did when resolverAddress null',
          () async {
        final did = 'did:test';

        await expectLater(
          UniversalDIDResolver.defaultResolver.resolveDid(did),
          throwsA(isA<SsiException>().having(
              (e) => e.code, 'code', SsiExceptionType.unableToResolveDid.code)),
        );
      });

      test('it throws exception on non-200 responses', () async {
        final did = 'did:test';
        // Use non-routable address to fail immediately instead of timing out
        final resolverAddress = 'http://0.0.0.0:1';
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
      // Use non-routable address to fail immediately instead of timing out
      final resolverAddress = 'http://0.0.0.0:1';
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
