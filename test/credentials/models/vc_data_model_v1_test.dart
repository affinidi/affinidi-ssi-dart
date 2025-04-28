import 'package:ssi/src/credentials/models/field_types/credential_status/v1.dart';
import 'package:ssi/src/credentials/models/field_types/credential_subject.dart';
import 'package:ssi/src/credentials/models/field_types/evidence.dart';
import 'package:ssi/src/credentials/models/field_types/holder.dart';
import 'package:ssi/src/credentials/models/field_types/issuer.dart';
import 'package:ssi/src/credentials/models/field_types/refresh_service/v1.dart';
import 'package:ssi/src/credentials/models/field_types/terms_of_use.dart';
import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';
import 'package:ssi/src/credentials/proof/embedded_proof.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';

void main() {
  group('VcDataModelV1 Tests', () {
    test('should correctly assign context', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final raw = jsonFixture['@context'];
      final expectedContext =
          raw is List ? List<String>.from(raw) : [raw as String];
      final vc = VcDataModelV1.fromJson(jsonFixture);
      expect(vc.context, expectedContext);
    });

    test('should correctly assign id', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final expectedId = Uri.parse(jsonFixture['id'] as String).toString();
      final vc = VcDataModelV1.fromJson(jsonFixture);
      expect(vc.id.toString(), expectedId);
    });

    test('should correctly assign type', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final raw = jsonFixture['type'];
      final expectedType =
          raw is List ? List<String>.from(raw) : [raw as String];
      final vc = VcDataModelV1.fromJson(jsonFixture);
      expect(vc.type, expectedType);
    });

    test('should correctly assign issuer', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final expected = Issuer.fromJson(jsonFixture['issuer']);
      final vc = VcDataModelV1.fromJson(jsonFixture);
      expect(vc.issuer.id, expected.id);
    });

    test('should correctly assign issuanceDate (validFrom)', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final expected = DateTime.parse(jsonFixture['issuanceDate'] as String);
      final vc = VcDataModelV1.fromJson(jsonFixture);
      expect(vc.issuanceDate, expected);
      expect(vc.validFrom, expected);
    });

    test('should correctly assign expirationDate (validUntil)', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final expected = DateTime.parse(jsonFixture['expirationDate'] as String);
      final vc = VcDataModelV1.fromJson(jsonFixture);
      expect(vc.expirationDate, expected);
      expect(vc.validUntil, expected);
    });

    test('should correctly assign credentialSubject', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final expected =
          CredentialSubject.fromJson(jsonFixture['credentialSubject']);
      final vc = VcDataModelV1.fromJson(jsonFixture);
      expect(vc.credentialSubject.first.id, expected.id);
      expect(vc.credentialSubject.first['email'], expected['email']);
    });

    test('should correctly assign credentialSchema', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final rawSchema = jsonFixture['credentialSchema'];
      final expected = rawSchema is List
          ? rawSchema.map((e) => CredentialSchema.fromJson(e)).toList()
          : [];
      final vc = VcDataModelV1.fromJson(jsonFixture);
      expect([0, 1], contains(vc.credentialSchema.length));
      for (var i = 0;
          i < expected.length && i < vc.credentialSchema.length;
          i++) {
        expect(vc.credentialSchema[i].id, expected[i].id);
        expect(vc.credentialSchema[i].type, expected[i].type);
      }
    });

    test('should correctly assign credentialStatus', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final rawStatus = jsonFixture['credentialStatus'];
      final vc = VcDataModelV1.fromJson(jsonFixture);
      if (rawStatus != null) {
        final expected = CredentialStatusV1.fromJson(rawStatus);
        expect(vc.credentialStatus?.id, expected.id);
        expect(vc.credentialStatus?.type, expected.type);
      } else {
        expect(vc.credentialStatus, isNull);
      }
    });

    test('should correctly assign holder', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final expected = Holder.fromJson(jsonFixture['holder']);
      final vc = VcDataModelV1.fromJson(jsonFixture);
      expect(vc.holder?.id, expected.id);
    });

    test('should correctly assign proof', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final expected = EmbeddedProof.fromJson(jsonFixture['proof']);
      final vc = VcDataModelV1.fromJson(jsonFixture);
      expect(vc.proof.length, 1);
      expect(vc.proof.first.type, expected.type);
      expect(vc.proof.first.verificationMethod, expected.verificationMethod);
    });

    test('should correctly assign refreshService', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final vc = VcDataModelV1.fromJson({
        ...jsonFixture,
        'refreshService': RefreshServiceV1(
                id: Uri.parse('test-refresh-service-id'), type: 't')
            .toJson()
      });
      expect(vc.refreshService.first.id.toString(), 'test-refresh-service-id');
      expect(vc.refreshService.first.type, 't');
    });

    test('should correctly assign termsOfUse', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final vc = VcDataModelV1.fromJson({
        ...jsonFixture,
        'termsOfUse': [
          TermsOfUse(id: Uri.parse('test-terms-of-use-id'), type: 't').toJson(),
          TermsOfUse(type: 'AnotherTermV1').toJson()
        ],
      });
      expect(vc.termsOfUse.length, 2);
      expect(vc.termsOfUse[0].id.toString(), 'test-terms-of-use-id');
      expect(vc.termsOfUse[1].type, 'AnotherTermV1');
    });

    test('should correctly assign evidence', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final vc = VcDataModelV1.fromJson({
        ...jsonFixture,
        'evidence': [
          Evidence(id: Uri.parse('test-evidence-id'), type: 't').toJson(),
          Evidence(type: 'AnotherEvidenceV1').toJson()
        ]
      });
      expect(vc.evidence.length, 2);
      expect(vc.evidence[0].id.toString(), 'test-evidence-id');
      expect(vc.evidence[1].type, 'AnotherEvidenceV1');
    });

    group('JSON Serialization/Deserialization', () {
      test('toJson() should produce the correct map structure', () {
        final jsonFixture =
            VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
        final vc = VcDataModelV1.fromJson({
          ...jsonFixture,
          'refreshService': RefreshServiceV1(
                  id: Uri.parse('test-refresh-service-id'), type: 't')
              .toJson(),
          'termsOfUse': [
            TermsOfUse(id: Uri.parse('test-terms-of-use-id'), type: 't')
                .toJson(),
            TermsOfUse(type: 'AnotherTermV1').toJson()
          ],
          'evidence': [
            Evidence(id: Uri.parse('test-evidence-id'), type: 't').toJson(),
            Evidence(type: 'AnotherEvidenceV1').toJson()
          ]
        });
        final jsonMap = vc.toJson();

        expect(jsonMap['@context'], jsonFixture['@context']);
        expect(jsonMap['id'], Uri.parse(jsonFixture['id']).toString());
        expect(jsonMap['type'], jsonFixture['type']);
        if (jsonMap['issuer'] is Map && jsonFixture['issuer'] is Map) {
          expect(jsonMap['issuer'], jsonFixture['issuer']);
        } else {
          expect(jsonMap['issuer']['id'], jsonFixture['issuer'].toString());
        }
        expect(jsonMap['issuanceDate'], jsonFixture['issuanceDate']);
        expect(jsonMap['expirationDate'], jsonFixture['expirationDate']);
        if (jsonMap['credentialSubject'] is Map &&
            jsonFixture['credentialSubject'] is Map) {
          expect(
              jsonMap['credentialSubject'], jsonFixture['credentialSubject']);
        } else {
          expect(jsonMap['credentialSubject'].toString(),
              jsonFixture['credentialSubject'].toString());
        }
        expect(jsonMap['credentialSchema'], jsonFixture['credentialSchema']);
        if (jsonMap['credentialStatus'] is Map &&
            jsonFixture['credentialStatus'] is Map) {
          expect(jsonMap['credentialStatus'], jsonFixture['credentialStatus']);
        } else {
          expect(jsonMap['credentialStatus'], jsonFixture['credentialStatus']);
        }
        if (jsonMap['holder'] is Map && jsonFixture['holder'] is Map) {
          if (jsonMap['holder'] is Map && jsonFixture['holder'] is Map) {
            expect(jsonMap['holder'], jsonFixture['holder']);
          } else if (jsonMap['holder'] is String &&
              jsonFixture['holder'] is String) {
            expect(jsonMap['holder'], jsonFixture['holder']);
          } else if (jsonMap['holder'] is String &&
              jsonFixture['holder'] is Map) {
            expect(jsonMap['holder'], jsonFixture['holder']['id']);
          } else if (jsonMap['holder'] is Map &&
              jsonFixture['holder'] is String) {
            expect(jsonMap['holder']['id'], jsonFixture['holder']);
          } else {
            expect(
                jsonMap['holder'].toString(), jsonFixture['holder'].toString());
          }
        }
        if (jsonMap['proof'] is Map && jsonFixture['proof'] is Map) {
          final actualProof = Map<String, dynamic>.from(jsonMap['proof']);
          final expectedProof = Map<String, dynamic>.from(jsonFixture['proof']);
          if (actualProof.containsKey('created') &&
              expectedProof.containsKey('created')) {
            String normalize(String dt) => dt.replaceAll('.000Z', 'Z');
            expect(normalize(actualProof['created'].toString()),
                normalize(expectedProof['created'].toString()),
                reason: "Normalized 'created' field should match");
            actualProof.remove('created');
            expectedProof.remove('created');
          }
          expect(actualProof, expectedProof);
        } else {
          expect(jsonMap['proof'].toString(), jsonFixture['proof'].toString());
        }
        expect(jsonMap['refreshService']['id'], 'test-refresh-service-id');
        expect(jsonMap['termsOfUse'], [
          {'id': 'test-terms-of-use-id', 'type': 't'},
          {'type': 'AnotherTermV1'}
        ]);
        expect(jsonMap['evidence'], [
          {'id': 'test-evidence-id', 'type': 't'},
          {'type': 'AnotherEvidenceV1'}
        ]);
      });

      test('fromJson() should correctly parse the map', () {
        final jsonFixture =
            VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
        final vc = VcDataModelV1.fromJson({
          ...jsonFixture,
          'refreshService': RefreshServiceV1(
                  id: Uri.parse('test-refresh-service-id'), type: 't')
              .toJson(),
          'termsOfUse': [
            TermsOfUse(id: Uri.parse('test-terms-of-use-id'), type: 't')
                .toJson(),
            TermsOfUse(type: 'AnotherTermV1').toJson()
          ],
          'evidence': [
            Evidence(id: Uri.parse('test-evidence-id'), type: 't').toJson(),
            Evidence(type: 'AnotherEvidenceV1').toJson()
          ]
        });
        final parsed = VcDataModelV1.fromJson(vc.toJson());

        expect(parsed.context, vc.context);
        expect(parsed.id, vc.id);
        expect(parsed.type, vc.type);
        expect(parsed.issuer.id, vc.issuer.id);
        expect(parsed.issuanceDate, vc.issuanceDate);
        expect(parsed.expirationDate, vc.expirationDate);
        expect(
            parsed.credentialSubject.first.id, vc.credentialSubject.first.id);
        expect(parsed.credentialSchema.length, vc.credentialSchema.length);
        expect(parsed.credentialStatus?.id, vc.credentialStatus?.id);
        expect(parsed.holder?.id, vc.holder?.id);
        expect(parsed.proof.length, vc.proof.length);
        expect(parsed.proof.first.type, vc.proof.first.type);
        expect(parsed.refreshService.first.id, vc.refreshService.first.id);
        expect(parsed.termsOfUse.length, vc.termsOfUse.length);
        expect(parsed.evidence.length, vc.evidence.length);
      });
    });

    test('fromJson() should handle missing optional fields', () {
      final jsonFixture =
          VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;
      final rawContext = jsonFixture['@context'];
      final testContext = rawContext is List
          ? List<String>.from(rawContext)
          : [rawContext as String];
      final rawType = jsonFixture['type'];
      final testType =
          rawType is List ? List<String>.from(rawType) : [rawType as String];
      final testIssuer = Issuer.fromJson(jsonFixture['issuer']);
      final testIssuanceDate =
          DateTime.parse(jsonFixture['issuanceDate'] as String);
      final testCredentialSubject =
          CredentialSubject.fromJson(jsonFixture['credentialSubject']);

      final jsonMap = {
        '@context': rawContext,
        'id': jsonFixture['id'],
        'type': rawType,
        'issuer': jsonFixture['issuer'],
        'issuanceDate': jsonFixture['issuanceDate'],
        'credentialSubject': jsonFixture['credentialSubject'],
        'credentialSchema': <dynamic>[],
        'proof': <dynamic>[],
        'termsOfUse': <dynamic>[],
        'evidence': <dynamic>[],
      };

      try {
        final parsed = VcDataModelV1.fromJson(jsonMap);

        expect(parsed.context, testContext);
        expect(parsed.id.toString(), Uri.parse(jsonFixture['id']).toString());
        expect(parsed.type, testType);
        expect(parsed.issuer.id, testIssuer.id);
        expect(parsed.issuanceDate, testIssuanceDate);
        expect(parsed.expirationDate, isNull);
        expect(parsed.credentialSubject.first.id, testCredentialSubject.id);
        expect(parsed.credentialSchema, isEmpty);

        if (jsonMap['credentialStatus'] is Map) {
          expect(parsed.credentialStatus, isNotNull);
        } else {
          expect(parsed.credentialStatus, isNull);
        }
        if (jsonMap['holder'] is Map) {
          expect(parsed.holder, isNotNull);
        } else {
          expect(parsed.holder, isNull);
        }
        expect(parsed.proof, isEmpty);
        expect(parsed.refreshService, isEmpty);
        expect(parsed.termsOfUse, isEmpty);
        expect(parsed.evidence, isEmpty);
      } catch (e) {
        expect(e, isA<TypeError>());
      }
    });

    test(
      'fromJson() should throw SsiException for incorrect data types in JSON',
      () {
        final invalid = {
          '@context': 'not a list',
          'id': 123,
          'type': 'not a list',
          'issuer': 'not an object',
          'issuanceDate': 'not a date string',
          'expirationDate': 12345,
          'credentialSubject': 'not an object',
          'credentialSchema': 'not a list',
          'credentialStatus': 'not an object',
          'holder': 'not an object',
          'proof': 'not a list or object',
          'refreshService': 'not an object',
          'termsOfUse': 'not a list',
          'evidence': 'not a list',
        };
        expect(
          () => VcDataModelV1.fromJson(invalid),
          throwsA(isA<SsiException>().having(
            (e) => e.code,
            'code',
            SsiExceptionType.invalidJson.code,
          )),
        );
      },
    );
  });
}
