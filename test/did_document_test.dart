import 'dart:convert';

import 'package:ssi/src/did/did_document.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';
import 'package:test/test.dart';

import 'fixtures/did_document_fixtures.dart';

void main() {
  group('Test Verification Method', () {
    test('JWK conversion for Ed25519', () async {
      final vm = VerificationMethodMultibase(
        id: '#key1',
        controller: 'did:example:1',
        type: 'Multikey',
        publicKeyMultibase: 'z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu',
      );

      final expectedJson = jsonDecode(r'''
        {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "Zmq-CJA17UpFeVmJ-nIKDuDEhUnoRSNIXFbxyBtCh6Y"
        }
      ''');

      expect(vm.asJwk().toJson(), expectedJson);
    });

    test('multicodec conversion for Ed25519', () async {
      final vm = VerificationMethodJwk(
        id: '#key1',
        controller: 'did:example:1',
        type: 'Multikey',
        publicKeyJwk: Jwk.fromJson({
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "Zmq-CJA17UpFeVmJ-nIKDuDEhUnoRSNIXFbxyBtCh6Y"
        }),
      );

      final expectedMultibase =
          'z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu';
      expect(vm.asMultiBase(), expectedMultibase);
    });

    test('JWK conversion for secp256k1', () async {
      final vm = VerificationMethodMultibase(
        id: '#key1',
        controller: 'did:example:1',
        type: 'Multikey',
        publicKeyMultibase: 'zQ3shvpfWjYk7DfbsyAEFQTfmz3qjeDmdNcJ8a1mhkps4qKGj',
      );

      final expectedJson = jsonDecode(r'''
        {
          "kty": "EC",
          "crv": "secp256k1",
          "x": "8G9rBdSs9mib1X_2K4ify7wFDLT4ZhoVD7aCy-jimUg",
          "y": "4D9aPYTmYa68Xw3OeFuFE33-l4JrSpQ8Bh4VkBdXvT8"
        }
      ''');

      expect(vm.asJwk().toJson(), expectedJson);
    });

    test('multicodec conversion for secp256k1', () async {
      final vm = VerificationMethodJwk(
        id: '#key1',
        controller: 'did:example:1',
        type: 'Multikey',
        publicKeyJwk: Jwk.fromJson({
          "kty": "EC",
          "crv": "secp256k1",
          "x": "8G9rBdSs9mib1X_2K4ify7wFDLT4ZhoVD7aCy-jimUg",
          "y": "4D9aPYTmYa68Xw3OeFuFE33-l4JrSpQ8Bh4VkBdXvT8"
        }),
      );

      final expectedMultibase =
          'zQ3shvpfWjYk7DfbsyAEFQTfmz3qjeDmdNcJ8a1mhkps4qKGj';
      expect(vm.asMultiBase(), expectedMultibase);
    });
  });

  group(
    "when parsing DidDocument from json",
    () {
      group("and receiving a valid json,", () {
        final didDoc =
            DidDocument.fromJson(DidDocumentFixtures.didDocumentValid);

        test("it retrieves correct id", () {
          expect(didDoc.id,
              "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io");
        });

        test("it retrieves correct authentication", () {
          expect(didDoc.authentication[0],
              "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-0");
          expect(didDoc.authentication[1], isA<VerificationMethod>());
        });

        test("it retrieves correct also know as", () {
          expect(didDoc.alsoKnownAs, [
            "did:web:ee958780-4507-44fb-9af6-a61fdsda54b0f.atlas.dev.affinidi.io"
          ]);
        });

        test("it retrieves correct capability invacation", () {
          expect(
            didDoc.capabilityInvocation[0],
            "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-0",
          );
          expect(didDoc.capabilityInvocation[1], isA<VerificationMethod>());
        });

        test("it retrieves correct capability delegation", () {
          expect(
            didDoc.capabilityDelegation[0],
            "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-1",
          );
          expect(didDoc.capabilityDelegation[1], isA<VerificationMethod>());
        });

        test("it retrieves correct aasertion method", () {
          expect(didDoc.assertionMethod[0],
              "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-0");
        });

        test("it retrieves correct verififcation methods", () {
          expect(
            didDoc.verificationMethod[0].id,
            "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-0",
          );
          expect(
            didDoc.verificationMethod[1].id,
            "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#key-1",
          );
          expect(didDoc.verificationMethod[0].type, "JsonWebKey2020");
        });

        test("it retrieves correct service", () {
          expect(didDoc.service[0].id,
              "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#service");
          expect(didDoc.service[0].type, "DIDCommMessaging");
        });

        test("it retrieves correct context", () {
          expect(
            didDoc.context
                .hasUrlContext(Uri.parse('https://www.w3.org/ns/did/v1')),
            true,
          );
        });

        test("it resolves key ids successfully", () {
          final newDidDoc = didDoc.resolveKeyIds();
          expect(newDidDoc.assertionMethod[0], didDoc.verificationMethod[0]);
        });
      });

      group("and recieve invalid json,", () {
        test("it throws format exception that ID is required", () {
          expect(
            () => DidDocument.fromJson(
                DidDocumentFixtures.didDocumentInvalidWithoutId),
            throwsA(
              isA<FormatException>().having((e) => e.message, "message",
                  'id property needed in did document'),
            ),
          );
        });
      });

      group("and recieve invalid json,", () {
        test("it throws exception that context cannot be null", () {
          expect(
            () => DidDocument.fromJson(
                DidDocumentFixtures.didDocumentInvalidWithoutContext),
            throwsA(
              isA<SsiException>().having((e) => e.code, "code",
                  SsiExceptionType.invalidDidDocument.code),
            ),
          );
        });
      });
    },
  );

  group("When parsing service endpoint from json", () {
    group("and recieving valid json,", () {
      final serviceEndpoint =
          ServiceEndpoint.fromJson(DidDocumentFixtures.serviceEndpointValid);
      test("it retrieves correct id", () {
        expect(serviceEndpoint.id,
            "did:web:ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io#service");
      });

      test("it retrieves correct type", () {
        expect(serviceEndpoint.type, "DIDCommMessaging");
      });

      test('it retrieves correct service endpoint', () {
        expect(serviceEndpoint.serviceEndpoint, [
          {
            "accept": ["didcomm/v2"],
            "routingKeys": [],
            "uri":
                "https://ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io"
          },
          {
            "accept": ["didcomm/v2"],
            "routingKeys": [],
            "uri":
                "wss://ee958780-4507-44bb-9ac6-a618bda54b0f.atlas.dev.affinidi.io/ws"
          }
        ]);
      });
    });
  });
}
