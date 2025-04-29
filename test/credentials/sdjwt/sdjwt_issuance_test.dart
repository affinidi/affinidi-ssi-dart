import 'dart:typed_data';

import 'package:ssi/src/credentials/models/field_types/credential_subject.dart';
import 'package:ssi/src/credentials/models/field_types/issuer.dart';
import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'package:ssi/src/credentials/sdjwt/sdjwt_dm_v2_suite.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('SD-JWT Issuance Tests', () {
    final testSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 1));

    late DidSigner signer;
    late SdJwtDm2Suite suite;

    setUp(() async {
      signer = await initSigner(testSeed);
      suite = SdJwtDm2Suite();
    });

    test('can issue a credential with default options', () async {
      final credential = MutableVcDataModelV2(
        context: [DMV2ContextUrl],
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: Issuer.uri('did:example:issuer'),
        type: {'VerifiableCredential', 'UniversityDegreeCredential'},
        validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
        validUntil: DateTime.parse('2028-01-01T12:00:00Z'),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'degree': {
              'type': 'BachelorDegree',
              'name': 'Bachelor of Science and Arts',
            },
          })
        ],
      );

      final issuedCredential = await suite.issue(
          VcDataModelV2.fromJson(credential.toJson()), signer);

      expect(issuedCredential, isNotNull);
      expect(issuedCredential.serialized, isNotNull);
      expect(issuedCredential.serialized, isA<String>());
      expect(
          issuedCredential.serialized, contains('~')); // Contains disclosures
      expect(issuedCredential.issuer.id.toString(), equals(signer.did));
      expect(issuedCredential.type, equals(credential.type));
      expect(issuedCredential.validFrom, equals(credential.validFrom));
      expect(issuedCredential.validUntil, equals(credential.validUntil));

      final sdJwt = issuedCredential.sdJwt;
      expect(sdJwt.header, contains('alg'));
      expect(sdJwt.header, contains('kid'));
      expect(sdJwt.payload, contains('@context'));
      expect(sdJwt.payload['_sd_alg'], isNotNull);

      final parsedCredential = suite.parse(issuedCredential.serialized);
      expect(parsedCredential.id, equals(credential.id));
      expect(parsedCredential.issuer.id.toString(), equals(signer.did));

      final isValid = await suite.verifyIntegrity(issuedCredential);
      expect(isValid, isTrue);
    });

    test('can issue a credential with custom disclosure frame', () async {
      final credential = MutableVcDataModelV2(
        context: [DMV2ContextUrl],
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: Issuer.uri('did:example:issuer'),
        type: {'VerifiableCredential', 'UniversityDegreeCredential'},
        validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
        validUntil: DateTime.parse('2028-01-01T12:00:00Z'),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'firstName': 'Rain',
            'lastName': 'Bow',
            'degree': {
              'type': 'BachelorDegree',
              'name': 'Bachelor of Science and Arts',
              'gpa': '3.8',
            },
          })
        ],
      );

      final disclosureFrame = {
        'credentialSubject': {
          '_sd': ['firstName', 'lastName'],
          'degree': {
            '_sd': ['gpa'],
          },
        },
      };

      final issuedCredential = await suite.issue(
        VcDataModelV2.fromJson(credential.toJson()),
        signer,
        options: SdJwtDm2Options(
          disclosureFrame: disclosureFrame,
        ),
      );

      expect(issuedCredential, isNotNull);
      expect(issuedCredential.serialized, isNotNull);

      final serialized = issuedCredential.serialized;
      final parts = serialized.split('~');
      expect(parts.length, greaterThan(1)); // At least one disclosure

      final isValid = await suite.verifyIntegrity(issuedCredential);
      expect(isValid, isTrue);
    });

    test('handles errors when issuing with invalid credential data', () async {
      final invalidCredential = MutableVcDataModelV2(
        context: [],
        issuer: Issuer.uri(''),
        type: {},
      );

      expect(
        () => suite.issue(
            VcDataModelV2.fromJson(invalidCredential.toJson()), signer),
        throwsA(isA<SsiException>()),
      );
    });
  });
}
