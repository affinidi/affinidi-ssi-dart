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
    'when parsing DidDocument from json',
    () {
      group('and receiving a valid json,', () {
        final didDoc =
            DidDocument.fromJson(DidDocumentFixtures.didDocumentValid);

        test('it retrieves correct id', () {
          expect(didDoc.id, 'did:web:example.com');
        });

        test('it retrieves correct authentication', () {
          expect(didDoc.authentication[0].id, 'did:web:example.com#key-0');
          expect(didDoc.authentication[1], isA<EmbeddedVerificationMethod>());
          expect(didDoc.authentication[1].id, 'did:web:example.com#key-2');
        });

        test('it retrieves correct also know as', () {
          expect(didDoc.alsoKnownAs, ['did:web:alias.example.com']);
        });

        test('it retrieves correct capability invacation', () {
          expect(
            didDoc.capabilityInvocation[0].id,
            'did:web:example.com#key-0',
          );
          expect(didDoc.capabilityInvocation[1],
              isA<EmbeddedVerificationMethod>());
          expect(
              didDoc.capabilityInvocation[1].id, 'did:web:example.com#key-2');
        });

        test('it retrieves correct capability delegation', () {
          expect(
            didDoc.capabilityDelegation[0].id,
            'did:web:example.com#key-1',
          );
          expect(didDoc.capabilityDelegation[1],
              isA<EmbeddedVerificationMethod>());
          expect(
              didDoc.capabilityDelegation[1].id, 'did:web:example.com#key-2');
        });

        test('it retrieves correct assertion method', () {
          expect(didDoc.assertionMethod[0].id, 'did:web:example.com#key-0');
          expect(didDoc.assertionMethod[1], isA<EmbeddedVerificationMethod>());
          expect(didDoc.assertionMethod[1].id, 'did:web:example.com#key-2');
        });

        test('it retrieves correct verification methods', () {
          expect(
            didDoc.verificationMethod[0].id,
            'did:web:example.com#key-0',
          );
          expect(
            didDoc.verificationMethod[1].id,
            'did:web:example.com#key-1',
          );
          expect(
            didDoc.verificationMethod[2].id,
            'did:web:example.com#key-2',
          );
          expect(didDoc.verificationMethod[0].type, 'JsonWebKey2020');
          expect(didDoc.verificationMethod[1].type, 'JsonWebKey2020');
          expect(didDoc.verificationMethod[2].type, 'JsonWebKey2020');
        });

        test('it retrieves correct service', () {
          expect(didDoc.service[0].id, 'did:web:example.com#service');
          expect(didDoc.service[0].type,
              const StringServiceType('GenericService'));
        });

        test('it retrieves correct context', () {
          expect(
            didDoc.context
                .hasUrlContext(Uri.parse('https://www.w3.org/ns/did/v1')),
            true,
          );
        });
      });

      group('and receiving invalid json,', () {
        test('it throws format exception that ID is required', () {
          expect(
            () => DidDocument.fromJson(
                DidDocumentFixtures.didDocumentInvalidWithoutId),
            throwsA(
              isA<FormatException>().having((e) => e.message, 'message',
                  'id property needed in did document'),
            ),
          );
        });
      });

      group('and receiving invalid json,', () {
        test('it throws exception that context cannot be null', () {
          expect(
            () => DidDocument.fromJson(
                DidDocumentFixtures.didDocumentInvalidWithoutContext),
            throwsA(
              isA<SsiException>().having((e) => e.code, 'code',
                  SsiExceptionType.invalidDidDocument.code),
            ),
          );
        });
      });
    },
  );

  group('When parsing service endpoint from json', () {
    group('and receiving valid json,', () {
      final serviceEndpoint =
          ServiceEndpoint.fromJson(DidDocumentFixtures.serviceEndpointValid);
      test('it retrieves correct id', () {
        expect(serviceEndpoint.id, 'did:web:example.com#service');
      });

      test('it retrieves correct type', () {
        expect(serviceEndpoint.type, const StringServiceType('GenericService'));
      });

      test('it handles lists with one element for type', () {
        final serviceEndpoint = ServiceEndpoint.fromJson(
            DidDocumentFixtures.serviceEndpointTypeListOneElement);

        expect(serviceEndpoint.type, 'DIDCommMessaging');
      });

      test('it throws an error for lists with two elements for type', () {
        expect(
            () => ServiceEndpoint.fromJson(
                  DidDocumentFixtures.serviceEndpointTypeListTwoElement,
                ),
            throwsFormatException);
      });

      test('it retrieves correct service endpoint', () {
        final endpointValue = serviceEndpoint.serviceEndpoint;
        expect(endpointValue, isA<SetEndpoint>());

        final setEndpoint = endpointValue as SetEndpoint;
        expect(setEndpoint.endpoints.length, 2);

        // Check first endpoint
        final firstEndpoint = setEndpoint.endpoints[0] as MapEndpoint;
        expect(firstEndpoint.data['uri'], 'https://example.com');
        expect(firstEndpoint.data['accept'], ['application/json']);
        expect(firstEndpoint.data['routingKeys'], <String>[]);

        // Check second endpoint
        final secondEndpoint = setEndpoint.endpoints[1] as MapEndpoint;
        expect(secondEndpoint.data['uri'], 'wss://example.com/ws');
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
            Jwk.fromJson({'kty': 'OKP', 'crv': 'Ed25519', 'x': 'abc'}),
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
            Jwk.fromJson({'kty': 'OKP', 'crv': 'Ed25519', 'x': 'abc'}),
      );

      final didDoc = DidDocument.create(
        id: 'did:example:all',
        alsoKnownAs: ['did:example:aka'],
        controller: ['did:example:ctrl'],
        verificationMethod: [vm],
        authentication: ['id'],
        keyAgreement: ['id'],
        service: <ServiceEndpoint>[],
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
          () => ServiceEndpoint.fromJson(
              {'type': 't', 'serviceEndpoint': <dynamic>[]}),
          throwsFormatException);
    });
    test('throws if type missing', () {
      expect(
          () => ServiceEndpoint.fromJson(
              {'id': 'i', 'serviceEndpoint': <dynamic>[]}),
          throwsFormatException);
    });
    test('throws if serviceEndpoint missing', () {
      expect(() => ServiceEndpoint.fromJson({'id': 'i', 'type': 't'}),
          throwsFormatException);
    });
    test('accepts map for serviceEndpoint', () {
      final se = ServiceEndpoint.fromJson({
        'id': 'i',
        'type': 't',
        'serviceEndpoint': <String, dynamic>{
          'uri': 'https://example.com',
        },
      });
      expect(se.id, 'i');
      expect(se.type, const StringServiceType('t'));
      expect(se.serviceEndpoint, isA<MapEndpoint>());

      final mapEndpoint = se.serviceEndpoint as MapEndpoint;
      expect(mapEndpoint.data['uri'], 'https://example.com');
    });
    test('toString returns json string', () {
      final se = ServiceEndpoint(
        id: 'id',
        type: const StringServiceType('type'),
        serviceEndpoint: const MapEndpoint({
          'accept': ['a'],
          'routingKeys': <String>[],
          'uri': 'u',
        }),
      );
      expect(jsonDecode(se.toString()), se.toJson());
    });

    test('accepts string for serviceEndpoint', () {
      final se = ServiceEndpoint.fromJson({
        'id': 'service1',
        'type': 'LinkedDomains',
        'serviceEndpoint': 'https://example.com',
      });
      expect(se.id, 'service1');
      expect(se.type, const StringServiceType('LinkedDomains'));
      expect(se.serviceEndpoint, isA<StringEndpoint>());

      final stringEndpoint = se.serviceEndpoint as StringEndpoint;
      expect(stringEndpoint.url, 'https://example.com');
    });

    test('accepts mixed list for serviceEndpoint', () {
      final se = ServiceEndpoint.fromJson({
        'id': 'service2',
        'type': 'ExampleService',
        'serviceEndpoint': [
          'https://example.com/endpoint1',
          {
            'uri': 'https://example.com/endpoint2',
            'accept': ['application/json'],
          },
        ],
      });
      expect(se.id, 'service2');
      expect(se.type, const StringServiceType('ExampleService'));
      expect(se.serviceEndpoint, isA<SetEndpoint>());

      final setEndpoint = se.serviceEndpoint as SetEndpoint;
      expect(setEndpoint.endpoints.length, 2);
      expect(setEndpoint.endpoints[0], isA<StringEndpoint>());
      expect(setEndpoint.endpoints[1], isA<MapEndpoint>());
    });

    test('preserves arbitrary service types', () {
      final se = ServiceEndpoint.fromJson({
        'id': 'social',
        'type': 'https://social.example/ExampleSocialMediaService',
        'serviceEndpoint': 'https://warbler.example/sal674',
      });

      expect(
          se.type,
          const StringServiceType(
              'https://social.example/ExampleSocialMediaService'));
      expect((se.serviceEndpoint as StringEndpoint).url,
          'https://warbler.example/sal674');
    });

    test('accepts list of strings for type', () {
      final se = ServiceEndpoint.fromJson({
        'id': 'service3',
        'type': ['LinkedDomains', 'CredentialRegistry'],
        'serviceEndpoint': 'https://example.com',
      });

      expect(se.type,
          const SetServiceType(['LinkedDomains', 'CredentialRegistry']));
      expect(se.serviceEndpoint, isA<StringEndpoint>());
    });

    test('serializes list of strings for type correctly', () {
      final se = ServiceEndpoint(
        id: 'service4',
        type: const SetServiceType(['Type1', 'Type2']),
        serviceEndpoint: const StringEndpoint('https://example.com'),
      );

      final json = se.toJson();
      expect(json['type'], ['Type1', 'Type2']);
      expect(json['id'], 'service4');
      expect(json['serviceEndpoint'], 'https://example.com');
    });
  });
}
