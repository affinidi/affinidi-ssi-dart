import 'package:ssi/src/credentials/models/credential_schema.dart';
import 'package:ssi/src/credentials/models/credential_status.dart';
import 'package:ssi/src/credentials/models/credential_subject.dart';
import 'package:ssi/src/credentials/models/holder.dart';
import 'package:ssi/src/credentials/models/issuer.dart';
import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';
import 'package:ssi/src/credentials/models/vc_models.dart';
import 'package:ssi/src/credentials/proof/embedded_proof.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';

void main() {
  group('VcDataModelV1 Tests', () {
    final jsonFixture =
        VerifiableCredentialDataFixtures.credentialWithProofDataModelV11;

    final fullVc = MutableVcDataModelV1.fromJson(jsonFixture);

    final testContext = jsonFixture['@context'];
    final testId = jsonFixture['id'];
    final testType = jsonFixture['type'];
    final testIssuer = Issuer.fromJson(jsonFixture['issuer']);
    final testIssuanceDate = DateTime.parse(jsonFixture['issuanceDate']);
    final testExpirationDate = DateTime.parse(jsonFixture['expirationDate']);
    final testCredentialSubject =
        CredentialSubject.fromJson(jsonFixture['credentialSubject']);
    final testCredentialSchema = (jsonFixture['credentialSchema'] as List)
        .map((e) => CredentialSchema.fromJson(e))
        .toList();
    final testCredentialStatus =
        CredentialStatus.fromJson(jsonFixture['credentialStatus']);
    final testHolder = Holder.fromJson(jsonFixture['holder']);
    final testProof = [EmbeddedProof.fromJson(jsonFixture['proof'])];
    final testRefreshService = RefreshService(id: 'test-refresh-service-id');
    final testTermsOfUse = [TermOfUse(id: 'test-terms-of-use-id')];
    final testEvidence = [Evidence(id: 'test-evidence-id')];

    test('should correctly assign context', () {
      expect(fullVc.context, testContext);
    });

    test('should correctly assign id', () {
      expect(fullVc.id, testId);
    });

    test('should correctly assign type', () {
      expect(fullVc.type, testType);
    });

    test('should correctly assign issuer', () {
      expect(fullVc.issuer, testIssuer);
      expect(fullVc.issuer.id, testIssuer.id);
    });

    test('should correctly assign issuanceDate (validFrom)', () {
      expect(fullVc.issuanceDate, testIssuanceDate);
      expect(fullVc.validFrom, testIssuanceDate);
    });

    test('should correctly assign expirationDate (validUntil)', () {
      expect(fullVc.expirationDate, testExpirationDate);
      expect(fullVc.validUntil, testExpirationDate);
    });

    test('should correctly assign credentialSubject', () {
      expect(fullVc.credentialSubject, testCredentialSubject);
      expect(fullVc.credentialSubject.id, testCredentialSubject.id);
      expect(fullVc.credentialSubject['email'], testCredentialSubject['email']);
    });

    test('should correctly assign credentialSchema', () {
      expect(fullVc.credentialSchema, testCredentialSchema);
      expect(fullVc.credentialSchema.length, 2);
    });

    test('should correctly assign credentialStatus', () {
      expect(fullVc.credentialStatus, testCredentialStatus);
      expect(fullVc.credentialStatus?.id, testCredentialStatus.id);
      expect(fullVc.credentialStatus?.type, testCredentialStatus.type);
    });

    test('should correctly assign holder', () {
      expect(fullVc.holder, testHolder);
      expect(fullVc.holder?.id, testHolder.id);
    });

    test('should correctly assign proof', () {
      expect(fullVc.proof, testProof);
      expect(fullVc.proof.length, 1);
      expect(fullVc.proof.first.type, testProof.first.type);
    });

    test('should correctly assign refreshService', () {
      expect(fullVc.refreshService, testRefreshService);
      expect(fullVc.refreshService?.id, testRefreshService.id);
      expect(fullVc.refreshService?.type, testRefreshService.type);
    });

    test('should correctly assign termsOfUse', () {
      expect(fullVc.termsOfUse, testTermsOfUse);
      expect(fullVc.termsOfUse.length, 2);
    });

    test('should correctly assign evidence', () {
      expect(fullVc.evidence, testEvidence);
      expect(fullVc.evidence.length, 2);
    });

    group('JSON Serialization/Deserialization', () {
      late Map<String, dynamic> jsonMap;

      setUpAll(() {
        jsonMap = fullVc.toJson();
      });

      test('toJson() should produce the correct map structure', () {
        expect(jsonMap['@context'], testContext);
        expect(jsonMap['id'], testId);
        expect(jsonMap['type'], testType);
        expect(jsonMap['issuer'], testIssuer.toJson());
        expect(jsonMap['issuanceDate'], testIssuanceDate.toIso8601String());
        expect(jsonMap['expirationDate'], testExpirationDate.toIso8601String());
        expect(jsonMap['credentialSubject'], testCredentialSubject.toJson());
        expect(jsonMap['credentialSchema'],
            testCredentialSchema.map((e) => e.toJson()).toList());
        expect(jsonMap['credentialStatus'], testCredentialStatus.toJson());
        expect(jsonMap['holder'], testHolder.toJson());
        expect(jsonMap['proof'], testProof.first.toJson());
        expect(jsonMap['refreshService'], testRefreshService.toJson());
        expect(jsonMap['termsOfUse'],
            testTermsOfUse.map((e) => e.toJson()).toList());
        expect(
            jsonMap['evidence'], testEvidence.map((e) => e.toJson()).toList());
      });

      test('fromJson() should correctly parse the map', () {
        final parsedVc = MutableVcDataModelV1.fromJson(jsonMap);

        expect(parsedVc.context, testContext);
        expect(parsedVc.id, testId);
        expect(parsedVc.type, testType);
        expect(parsedVc.issuer.id, testIssuer.id);
        expect(parsedVc.issuanceDate, testIssuanceDate);
        expect(parsedVc.expirationDate, testExpirationDate);
        expect(parsedVc.credentialSubject.id, testCredentialSubject.id);
        expect(
            parsedVc.credentialSubject['name'], testCredentialSubject['name']);
        expect(parsedVc.credentialSubject['degree'],
            testCredentialSubject['degree']);
        expect(parsedVc.credentialSchema.length, testCredentialSchema.length);
        expect(parsedVc.credentialSchema[0].id, testCredentialSchema[0].id);
        expect(parsedVc.credentialSchema[0].type, testCredentialSchema[0].type);
        expect(parsedVc.credentialSchema[1].id, testCredentialSchema[1].id);
        expect(parsedVc.credentialSchema[1].type, testCredentialSchema[1].type);
        expect(parsedVc.credentialStatus?.id, testCredentialStatus.id);
        expect(parsedVc.credentialStatus?.type, testCredentialStatus.type);
        expect(parsedVc.holder?.id, testHolder.id);
        expect(parsedVc.proof.length, 1);
        expect(parsedVc.proof.first.type, testProof.first.type);
        expect(parsedVc.proof.first.created, testProof.first.created);
        expect(parsedVc.proof.first.verificationMethod,
            testProof.first.verificationMethod);
        expect(parsedVc.proof.first.proofPurpose, testProof.first.proofPurpose);
        expect(parsedVc.proof.first.proofValue, testProof.first.proofValue);
        expect(parsedVc.refreshService?.id, testRefreshService.id);
        expect(parsedVc.refreshService?.type, testRefreshService.type);
        expect(parsedVc.termsOfUse.length, testTermsOfUse.length);
        expect(parsedVc.termsOfUse[0].id, testTermsOfUse[0].id);
        expect(parsedVc.termsOfUse[0].type, testTermsOfUse[0].type);
        expect(parsedVc.termsOfUse[1].type, testTermsOfUse[1].type);
        expect(parsedVc.evidence.length, testEvidence.length);
        expect(parsedVc.evidence[0].id, testEvidence[0].id);
        expect(parsedVc.evidence[0].type, testEvidence[0].type);
        expect(parsedVc.evidence[1].type, testEvidence[1].type);
      });
    });

    group('JSON Deserialization Invalid Data', () {
      test('fromJson() should handle missing optional fields', () {
        final jsonMap = {
          '@context': testContext,
          'id': testId,
          'type': testType,
          'issuer': testIssuer.toJson(),
          'issuanceDate': testIssuanceDate.toIso8601String(),
          'credentialSubject': testCredentialSubject.toJson(),
        };

        final parsedVc = MutableVcDataModelV1.fromJson(jsonMap);

        expect(parsedVc.context, testContext);
        expect(parsedVc.id, testId);
        expect(parsedVc.type, testType);
        expect(parsedVc.issuer.id, testIssuer.id);
        expect(parsedVc.issuanceDate, testIssuanceDate);
        expect(parsedVc.expirationDate, isNull);
        expect(parsedVc.credentialSubject.id, testCredentialSubject.id);
        expect(parsedVc.credentialSchema, isEmpty);
        expect(parsedVc.credentialStatus, isNull);
        expect(parsedVc.holder, isNull);
        expect(parsedVc.proof, isEmpty);
        expect(parsedVc.refreshService, isNull);
        expect(parsedVc.termsOfUse, isEmpty);
        expect(parsedVc.evidence, isEmpty);
      });

      test(
          'fromJson() should throw SsiException for incorrect data types in JSON',
          () {
        final jsonMapWithInvalidTypes = {
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
            () => MutableVcDataModelV1.fromJson(jsonMapWithInvalidTypes),
            throwsA(isA<SsiException>().having(
                (e) => e.code, 'code', SsiExceptionType.invalidJson.code)));
      });
    });
  });
}
