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
      test('it resolves successfully', () async {
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

    group('using did:webvh,', () {
      test('it resolves successfully', () async {
        // cargo run --package didwebvh-rs:0.1.17 --example resolve
        // "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs" > diddoc.json

        // https://identity.foundation/didwebvh-implementations/implementations/affinidi-didwebvh-rs/did.jsonl

        // DID Document:
        // {
        //   "@context": [
        //     "https://www.w3.org/ns/did/v1"
        //   ],
        //   "assertionMethod": [
        //     "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"
        //   ],
        //   "authentication": [
        //     "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"
        //   ],
        //   "id": "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs",
        //   "keyAgreement": [
        //     "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"
        //   ],
        //   "service": [
        //     {
        //       "@context": "https://identity.foundation/linked-vp/contexts/v1",
        //       "id": "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#whois",
        //       "serviceEndpoint": "https://identity.foundation/didwebvh-implementations/implementations/affinidi-didwebvh-rs/whois.vp",
        //       "type": "LinkedVerifiablePresentation"
        //     },
        //     {
        //       "id": "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#files",
        //       "serviceEndpoint": "https://identity.foundation/didwebvh-implementations/implementations/affinidi-didwebvh-rs/",
        //       "type": "relativeRef"
        //     }
        //   ],
        //   "verificationMethod": [
        //     {
        //       "controller": "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs",
        //       "id": "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0",
        //       "publicKeyMultibase": "z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV",
        //       "type": "Multikey"
        //     }
        //   ]
        // }

        // WebVH Metadata:
        // {
        //   "versionId": "2-QmUCFFYYGBJhzZqyouAtvRJ7ULdd8FqSUvwb61FPTMH1Aj",
        //   "versionTime": "2025-07-13T23:44:37Z",
        //   "created": "2025-07-13T23:43:58Z",
        //   "updated": "2025-07-13T23:44:37Z",
        //   "scid": "Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai",
        //   "portable": true,
        //   "deactivated": false,
        //   "witness": {
        //     "threshold": 3,
        //     "witnesses": [
        //       {
        //         "id": "did:key:z6Mkih1iaNrtSYkynhqsVBCsetmGpv1YnANyzGZHzZSZJeG1"
        //       },
        //       {
        //         "id": "did:key:z6MkqmMLmWAMs357diZ4wYJMEVwEsPjau8X5BktJNTRtTWEv"
        //       },
        //       {
        //         "id": "did:key:z6MkoWf85ozvizXJUqfb3CrzXTDVYRQkkhHDa29GErDivZ7U"
        //       },
        //       {
        //         "id": "did:key:z6MkknMS6hC8bWwpHFax1uBkHYzjd4qyaQJB3es12d12mTYH"
        //       }
        //     ]
        //   },
        //   "watchers": [
        //     "https://watcher1.affinidi.com/"
        //   ]
        // }

        final did =
            'did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs';
        final String didDocumentWithControllerWebvh =
            '{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"authentication":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","keyAgreement":["did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0"],"service":[{"@context":"https://identity.foundation/linked-vp/contexts/v1","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#whois","serviceEndpoint":"https://identity.foundation/didwebvh-implementations/implementations/affinidi-didwebvh-rs/whois.vp","type":"LinkedVerifiablePresentation"},{"id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#files","serviceEndpoint":"https://identity.foundation/didwebvh-implementations/implementations/affinidi-didwebvh-rs/","type":"relativeRef"}],"verificationMethod":[{"controller":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs","id":"did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs#key-0","publicKeyMultibase":"z6MkmCx6AZNHKfJLZtdtWsPMWx26foZ8B6orqVqHwUEFsEWV","type":"Multikey"}]}';

        final expectedDidDoc = jsonDecode(didDocumentWithControllerWebvh);
        final resolvedDidDoc =
            await UniversalDIDResolver.defaultResolver.resolveDid(did);
        expect(resolvedDidDoc.toJson()['id'], expectedDidDoc['id']);
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
