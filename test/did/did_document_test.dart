import 'dart:convert';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../fixtures/did_document_fixtures.dart';

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
  });

  group(
    "when parsing DidDocument from json",
    () {
      group("and receiving a valid json,", () {
        final didDoc =
            DidDocument.fromJson(DidDocumentFixtures.didDocumentValid);

        test("it retrieves correct id", () {
          expect(didDoc.id, "did:web:example.com");
        });

        test("it retrieves correct authentication", () {
          expect(didDoc.authentication[0].id, "did:web:example.com#key-0");
          expect(didDoc.authentication[1], isA<EmbeddedVerificationMethod>());
          expect(didDoc.authentication[1].id, "did:web:example.com#key-2");
        });

        test("it retrieves correct also know as", () {
          expect(didDoc.alsoKnownAs, ["did:web:alias.example.com"]);
        });

        test("it retrieves correct capability invacation", () {
          expect(
            didDoc.capabilityInvocation[0].id,
            "did:web:example.com#key-0",
          );
          expect(didDoc.capabilityInvocation[1],
              isA<EmbeddedVerificationMethod>());
          expect(
              didDoc.capabilityInvocation[1].id, "did:web:example.com#key-2");
        });

        test("it retrieves correct capability delegation", () {
          expect(
            didDoc.capabilityDelegation[0].id,
            "did:web:example.com#key-1",
          );
          expect(didDoc.capabilityDelegation[1],
              isA<EmbeddedVerificationMethod>());
          expect(
              didDoc.capabilityDelegation[1].id, "did:web:example.com#key-2");
        });

        test("it retrieves correct assertion method", () {
          expect(didDoc.assertionMethod[0].id, "did:web:example.com#key-0");
          expect(didDoc.assertionMethod[1], isA<EmbeddedVerificationMethod>());
          expect(didDoc.assertionMethod[1].id, "did:web:example.com#key-2");
        });

        test("it retrieves correct verification methods", () {
          expect(
            didDoc.verificationMethod[0].id,
            "did:web:example.com#key-0",
          );
          expect(
            didDoc.verificationMethod[1].id,
            "did:web:example.com#key-1",
          );
          expect(
            didDoc.verificationMethod[2].id,
            "did:web:example.com#key-2",
          );
          expect(didDoc.verificationMethod[0].type, "JsonWebKey2020");
          expect(didDoc.verificationMethod[1].type, "JsonWebKey2020");
          expect(didDoc.verificationMethod[2].type, "JsonWebKey2020");
        });

        test("it retrieves correct service", () {
          expect(didDoc.service[0].id, "did:web:example.com#service");
          expect(didDoc.service[0].type, "DIDCommMessaging");
        });

        test("it retrieves correct context", () {
          expect(
            didDoc.context
                .hasUrlContext(Uri.parse('https://www.w3.org/ns/did/v1')),
            true,
          );
        });
      });

      group("and receiving invalid json,", () {
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

      group("and receiving invalid json,", () {
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
    group("and receiving valid json,", () {
      final serviceEndpoint =
          ServiceEndpoint.fromJson(DidDocumentFixtures.serviceEndpointValid);
      test("it retrieves correct id", () {
        expect(serviceEndpoint.id, "did:web:example.com#service");
      });

      test("it retrieves correct type", () {
        expect(serviceEndpoint.type, "DIDCommMessaging");
      });

      test('it retrieves correct service endpoint', () {
        final endpoints = serviceEndpoint.serviceEndpoint;
        expect(endpoints.length, 2);
        expect(endpoints[0].uri, "https://example.com");
        expect(endpoints[0].accept, ["didcomm/v2"]);
        expect(endpoints[0].routingKeys, []);
        expect(endpoints[1].uri, "wss://example.com/ws");
      });
    });
  });

  group('VerificationMethod', () {
    test('fromJson throws if no key material', () {
      expect(
          () => EmbeddedVerificationMethod.fromJson(
              {'id': 'id', 'type': 'type', 'controller': 'controller'}),
          throwsA(isA<SsiException>()));
    });
    test('toJson roundtrip for Jwk', () {
      final orig = VerificationMethodJwk(
        id: 'id',
        controller: 'controller',
        type: 'JsonWebKey2020',
        publicKeyJwk:
            Jwk.fromJson({"kty": "OKP", "crv": "Ed25519", "x": "abc"}),
      );
      final json = orig.toJson();
      final parsed = EmbeddedVerificationMethod.fromJson(json);
      expect(parsed.toJson(), json);
    });
    test('toJson roundtrip for Multibase', () {
      final orig = VerificationMethodMultibase(
        id: 'id',
        controller: 'controller',
        type: 'Multikey',
        publicKeyMultibase: 'z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu',
      );
      final json = orig.toJson();
      final parsed = EmbeddedVerificationMethod.fromJson({
        ...json,
        'publicKeyMultibase':
            'z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu',
      });
      expect(parsed.toJson(), json);
    });
  });

  group('DidDocument', () {
    test('toJson roundtrip', () {
      final didDoc = DidDocument.fromJson(DidDocumentFixtures.didDocumentValid);
      final json = didDoc.toJson();
      final didDoc2 = DidDocument.fromJson(json);
      expect(didDoc2.toJson(), json);
    });
    test('handles empty lists', () {
      final didDoc = DidDocument.create(id: 'did:example:empty');
      final json = didDoc.toJson();
      expect(json['id'], 'did:example:empty');
      expect(json['alsoKnownAs'], isNull);
      expect(json['controller'], isNull);
      expect(json['verificationMethod'], isNull);
      expect(json['authentication'], isNull);
      expect(json['keyAgreement'], isNull);
      expect(json['service'], isNull);
      expect(json['assertionMethod'], isNull);
      expect(json['capabilityDelegation'], isNull);
      expect(json['capabilityInvocation'], isNull);
    });
    test('can be constructed with all fields', () {
      final vm = VerificationMethodJwk(
        id: 'id',
        controller: 'controller',
        type: 'JsonWebKey2020',
        publicKeyJwk:
            Jwk.fromJson({"kty": "OKP", "crv": "Ed25519", "x": "abc"}),
      );

      final didDoc = DidDocument.create(
        id: 'did:example:all',
        alsoKnownAs: ['did:example:aka'],
        controller: ['did:example:ctrl'],
        verificationMethod: [vm],
        authentication: ['id'],
        keyAgreement: ['id'],
        service: [],
        assertionMethod: ['id'],
        capabilityDelegation: ['id'],
        capabilityInvocation: ['id'],
      );
      expect(didDoc.id, 'did:example:all');
      expect(didDoc.alsoKnownAs, isNotEmpty);
      expect(didDoc.controller, isNotEmpty);
      expect(didDoc.verificationMethod, isNotEmpty);
      expect(didDoc.authentication, isNotEmpty);
      expect(didDoc.keyAgreement, isNotEmpty);
      expect(didDoc.assertionMethod, isNotEmpty);
      expect(didDoc.capabilityDelegation, isNotEmpty);
      expect(didDoc.capabilityInvocation, isNotEmpty);
    });
  });

  group('ServiceEndpoint', () {
    test('throws if id missing', () {
      expect(
          () => ServiceEndpoint.fromJson({'type': 't', 'serviceEndpoint': []}),
          throwsFormatException);
    });
    test('throws if type missing', () {
      expect(() => ServiceEndpoint.fromJson({'id': 'i', 'serviceEndpoint': []}),
          throwsFormatException);
    });
    test('throws if serviceEndpoint missing', () {
      expect(() => ServiceEndpoint.fromJson({'id': 'i', 'type': 't'}),
          throwsFormatException);
    });
    test('throws if serviceEndpoint is not a list', () {
      expect(
          () => ServiceEndpoint.fromJson(
              {'id': 'i', 'type': 't', 'serviceEndpoint': {}}),
          throwsFormatException);
    });
    test('toString returns json string', () {
      final se = ServiceEndpoint(
        id: 'id',
        type: 'type',
        serviceEndpoint: [
          DIDCommServiceEndpoint(accept: ['a'], routingKeys: [], uri: 'u')
        ],
      );
      expect(jsonDecode(se.toString()), se.toJson());
    });
  });
}
