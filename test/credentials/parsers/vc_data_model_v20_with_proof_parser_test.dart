import 'package:ssi/src/credentials/parsers/vc_data_model_v2_with_proof_parser.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';
import 'package:test/test.dart';

void main() {
  group('VcDataModelV20WithProofParser', () {
    late VcDataModelV2WithProofParser parser;

    setUp(() {
      parser = VcDataModelV2WithProofParser();
    });

    group('canParse', () {
      test('returns true for valid VC 2.0 with proof', () {
        final data = {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          'id': 'http://example.edu/credentials/3732',
          'type': ['VerifiableCredential', 'UniversityDegreeCredential'],
          'issuer': 'https://example.edu/issuers/14',
          'validFrom': '2010-01-01T19:23:24Z',
          'credentialSubject': {
            'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
            'degree': {
              'type': 'BachelorDegree',
              'name': 'Bachelor of Science and Arts'
            }
          },
          "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "created": "2021-11-13T18:19:39Z",
            "verificationMethod": "https://university.example/issuers/14#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "z58DAdFfa9SkqZMVPxAQp...jQCrfFPP2oumHKtz"
          }
        };

        expect(parser.canParse(data), isTrue);
      });


      test('returns false for missing v2 context', () {
        final data = {
          '@context': ['https://www.w3.org/ns/credentials/v1'],
          'id': 'http://example.edu/credentials/3732',
          'type': ['VerifiableCredential'],
          'issuer': 'https://example.edu/issuers/14',
          'validFrom': '2010-01-01T19:23:24Z',
          'credentialSubject': {
            'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21'
          },
          'proof': {'type': 'DataIntegrityProof'}
        };

        expect(parser.canParse(data), isFalse);
      });

      test('returns false for missing proof', () {
        final data = {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          'id': 'http://example.edu/credentials/3732',
          'type': ['VerifiableCredential'],
          'issuer': 'https://example.edu/issuers/14',
          'validFrom': '2010-01-01T19:23:24Z',
          'credentialSubject': {'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21'}
        };

        expect(parser.canParse(data), isFalse);
      });
    });

    group('parse', () {
      test('successfully parses valid VC 2.0 with proof', () {
        final data = {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          'id': 'http://example.edu/credentials/3732',
          'type': ['VerifiableCredential', 'UniversityDegreeCredential'],
          'issuer': 'https://example.edu/issuers/14',
          'validFrom': '2010-01-01T19:23:24Z',
          'credentialSubject': {
            'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
            'degree': {
              'type': 'BachelorDegree',
              'name': 'Bachelor of Science and Arts'
            }
          },

          'proof': {'type': 'DataIntegrityProof'}
        };

        final credential = parser.parse(data);
        expect(credential.id, equals('http://example.edu/credentials/3732'));
        expect(credential.issuer, equals('https://example.edu/issuers/14'));
        expect(credential.type,
            equals(['VerifiableCredential', 'UniversityDegreeCredential']));
        expect(credential.validFrom,
            equals(DateTime.parse('2010-01-01T19:23:24Z')));
      });
      test('throws when missing required properties', () {
        final data = {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          'proof': {'type': 'DataIntegrityProof'}
        };

        expect(
          () => parser.parse(data),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.unableToParseVerifiableCredential.code,
            ),
          ),
        );
      });

      test('throws when context is invalid', () {
        final data = {
          '@context': ['https://www.w3.org/ns/credentials/v1'],
          'id': 'http://example.edu/credentials/3732',
          'type': ['VerifiableCredential'],
          'issuer': 'https://example.edu/issuers/14',
          'validFrom': '2010-01-01T19:23:24Z',
          'credentialSubject': {
            'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21'
          },
          'proof': {'type': 'DataIntegrityProof'}
        };

        expect(
          () => parser.parse(data),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.unableToParseVerifiableCredential.code,
            ),
          ),
        );
      });

      test('throws when validFrom is invalid', () {
        final data = {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          'id': 'http://example.edu/credentials/3732',
          'type': ['VerifiableCredential'],
          'issuer': 'https://example.edu/issuers/14',
          'validFrom': 'invalid-date',
          'credentialSubject': {
            'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21'
          },
          'proof': {'type': 'DataIntegrityProof'}
        };

        expect(
          () => parser.parse(data),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.unableToParseVerifiableCredential.code,
            ),
          ),
        );
      });

      test('throws when credentialSubject is invalid', () {
        final data = {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          'id': 'http://example.edu/credentials/3732',
          'type': ['VerifiableCredential'],
          'issuer': 'https://example.edu/issuers/14',
          'validFrom': '2010-01-01T19:23:24Z',
          'credentialSubject': 'not-an-object',
          'proof': {'type': 'DataIntegrityProof'}
        };

        expect(
          () => parser.parse(data),
          throwsA(
            isA<SsiException>().having(
              (e) => e.code,
              'code',
              SsiExceptionType.unableToParseVerifiableCredential.code,
            ),
          ),
        );
      });
    });
  });
}
