import 'package:ssi/src/credentials/models/credential_schema.dart';
import 'package:ssi/src/credentials/models/credential_status.dart';
import 'package:ssi/src/credentials/models/credential_subject.dart';
import 'package:ssi/src/credentials/models/holder.dart';
import 'package:ssi/src/credentials/models/issuer.dart';
import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'package:ssi/src/credentials/models/vc_models.dart';
import 'package:ssi/src/credentials/proof/embedded_proof.dart';
import 'package:test/test.dart';

void main() {
  group('VcDataModelV2 Tests', () {
    final testContext = [
      MutableVcDataModelV2.contextUrl,
      'https://example.org/context/v2'
    ];
    const testId = 'http://example.edu/credentials/abcde';
    final testType = ['VerifiableCredential', 'ExampleCredentialV2'];
    final testIssuer = Issuer(id: 'did:example:issuerV2');
    final testValidFrom = DateTime.utc(2024, 01, 01, 12, 0, 0);
    final testValidUntil = DateTime.utc(2025, 01, 01, 12, 0, 0);
    final testCredentialSubject = CredentialSubject(
      id: 'did:example:subjectV2',
      claims: {'email': 'user@affinidi.com'},
    );
    final testCredentialSchema = [
      CredentialSchema(
          domain: 'https://example.org/schemas/v2',
          schema: 'example',
          type: 'JsonSchemaValidator2018'),
      CredentialSchema(
          domain: 'https://example.org/schemas/v2',
          schema: 'another',
          type: 'AnotherSchemaValidator'),
    ];
    final testCredentialStatus = CredentialStatus(
      id: Uri.parse('https://example.edu/status/v2/1'),
      type: 'CredentialStatusList2021',
    );
    final testHolder = Holder(id: Uri.parse('did:example:holderV2'));
    final testProof = [
      EmbeddedProof(
        type: 'DataIntegrityProof',
        created: DateTime.utc(2024, 01, 01, 12, 5, 0),
        verificationMethod: 'did:example:issuerV2#keys-1',
        proofPurpose: 'assertionMethod',
        proofValue: 'zABC...',
        cryptosuite: 'eddsa-jcs-2022',
      ),
      EmbeddedProof(
        type: 'AnotherProofType',
        created: DateTime.utc(2024, 01, 01, 12, 6, 0),
        verificationMethod: 'did:example:issuerV2#keys-2',
        proofPurpose: 'authentication',
        proofValue: 'zXYZ...',
        cryptosuite: 'ecdsa-jcs-2019',
      ),
    ];
    final testRefreshService = RefreshService(
      id: 'https://example.edu/refresh/v2/1',
      type: 'ManualRefreshService2021',
    );
    final testTermsOfUse = [
      TermOfUse(
        id: 'https://example.com/tos/v2/1',
        type: 'IssuerPolicyV2',
      ),
      TermOfUse(
        type: 'AnotherTermV2',
      ),
    ];
    final testEvidence = [
      Evidence(
        id: 'https://example.edu/evidence/v2/1',
        type: 'DocumentVerificationV2',
      ),
      Evidence(
        type: 'AnotherEvidenceV2',
      ),
    ];

    final fullVc = MutableVcDataModelV2(
      context: testContext,
      id: testId,
      type: testType,
      issuer: testIssuer,
      validFrom: testValidFrom,
      validUntil: testValidUntil,
      credentialSubject: testCredentialSubject,
      credentialSchema: testCredentialSchema,
      credentialStatus: testCredentialStatus,
      holder: testHolder,
      proof: testProof,
      refreshService: testRefreshService,
      termsOfUse: testTermsOfUse,
      evidence: testEvidence,
    );

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

    test('should correctly assign validFrom', () {
      expect(fullVc.validFrom, testValidFrom);
    });

    test('should correctly assign validUntil', () {
      expect(fullVc.validUntil, testValidUntil);
    });

    test('should correctly assign credentialSubject', () {
      expect(fullVc.credentialSubject, testCredentialSubject);
      expect(fullVc.credentialSubject.id, testCredentialSubject.id);
      expect(fullVc.credentialSubject['name'], testCredentialSubject['name']);
      expect(fullVc.credentialSubject['role'], testCredentialSubject['role']);
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
      expect(fullVc.proof.length, 2);
      expect(fullVc.proof.first.type, testProof.first.type);
      expect(fullVc.proof.last.type, testProof.last.type);
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
      late Map<String, dynamic> jsonMapSingleProof;

      final vcMultiProof = fullVc;

      final vcSingleProof = MutableVcDataModelV2(
        context: testContext,
        id: testId,
        type: testType,
        issuer: testIssuer,
        validFrom: testValidFrom,
        validUntil: testValidUntil,
        credentialSubject: testCredentialSubject,
        credentialSchema: [testCredentialSchema.first],
        credentialStatus: testCredentialStatus,
        holder: testHolder,
        proof: [testProof.first],
        refreshService: testRefreshService,
        termsOfUse: [testTermsOfUse.first],
        evidence: [testEvidence.first],
      );

      setUpAll(() {
        jsonMap = vcMultiProof.toJson();
        jsonMapSingleProof = vcSingleProof.toJson();
      });

      test('toJson() should produce correct map (multiple proofs)', () {
        expect(jsonMap['@context'], testContext);
        expect(jsonMap['id'], testId);
        expect(jsonMap['type'], testType);
        expect(jsonMap['issuer'], testIssuer.toJson());
        expect(jsonMap['validFrom'], testValidFrom.toIso8601String());
        expect(jsonMap['validUntil'], testValidUntil.toIso8601String());
        expect(jsonMap['credentialSubject'], testCredentialSubject.toJson());
        expect(jsonMap['credentialSchema'],
            testCredentialSchema.map((e) => e.toJson()).toList());
        expect(jsonMap['credentialStatus'], testCredentialStatus.toJson());
        expect(jsonMap['holder'], testHolder.toJson());
        expect(jsonMap['proof'], testProof.map((e) => e.toJson()).toList());
        expect(jsonMap['refreshService'], testRefreshService.toJson());
        expect(jsonMap['termsOfUse'],
            testTermsOfUse.map((e) => e.toJson()).toList());
        expect(
            jsonMap['evidence'], testEvidence.map((e) => e.toJson()).toList());
      });

      test('toJson() should produce correct map (single proof)', () {
        expect(jsonMapSingleProof['@context'], testContext);
        expect(jsonMapSingleProof['id'], testId);
        expect(jsonMapSingleProof['type'], testType);
        expect(jsonMapSingleProof['issuer'], testIssuer.toJson());
        expect(
            jsonMapSingleProof['validFrom'], testValidFrom.toIso8601String());
        expect(
            jsonMapSingleProof['validUntil'], testValidUntil.toIso8601String());
        expect(jsonMapSingleProof['credentialSubject'],
            testCredentialSubject.toJson());
        expect(jsonMapSingleProof['credentialSchema'],
            testCredentialSchema.first.toJson());
        expect(jsonMapSingleProof['credentialStatus'],
            testCredentialStatus.toJson());
        expect(jsonMapSingleProof['holder'], testHolder.toJson());
        expect(jsonMapSingleProof['proof'], testProof.first.toJson());
        expect(
            jsonMapSingleProof['refreshService'], testRefreshService.toJson());
        expect(jsonMapSingleProof['termsOfUse'], testTermsOfUse.first.toJson());
        expect(jsonMapSingleProof['evidence'], testEvidence.first.toJson());
      });

      test('fromJson() should correctly parse map (multiple proofs)', () {
        final parsedVc = MutableVcDataModelV2.fromJson(jsonMap);

        expect(parsedVc.context, testContext);
        expect(parsedVc.id, testId);
        expect(parsedVc.type, testType);
        expect(parsedVc.issuer.id, testIssuer.id);
        expect(parsedVc.validFrom, testValidFrom);
        expect(parsedVc.validUntil, testValidUntil);
        expect(parsedVc.credentialSubject.id, testCredentialSubject.id);
        expect(
            parsedVc.credentialSubject['name'], testCredentialSubject['name']);
        expect(
            parsedVc.credentialSubject['role'], testCredentialSubject['role']);
        expect(parsedVc.credentialSchema.length, testCredentialSchema.length);
        expect(parsedVc.credentialSchema[0].id, testCredentialSchema[0].id);
        expect(parsedVc.credentialSchema[1].id, testCredentialSchema[1].id);
        expect(parsedVc.credentialStatus?.id, testCredentialStatus.id);
        expect(parsedVc.holder?.id, testHolder.id);
        expect(parsedVc.proof.length, testProof.length);
        expect(parsedVc.proof[0].type, testProof[0].type);
        expect(parsedVc.proof[0].cryptosuite, testProof[0].cryptosuite);
        expect(parsedVc.proof[1].type, testProof[1].type);
        expect(parsedVc.proof[1].cryptosuite, testProof[1].cryptosuite);
        expect(parsedVc.refreshService?.id, testRefreshService.id);
        expect(parsedVc.termsOfUse.length, testTermsOfUse.length);
        expect(parsedVc.evidence.length, testEvidence.length);
      });

      test('fromJson() should correctly parse map (single proof object)', () {
        final parsedVc = MutableVcDataModelV2.fromJson(jsonMapSingleProof);

        expect(parsedVc.context, testContext);
        expect(parsedVc.id, testId);
        expect(parsedVc.type, testType);
        expect(parsedVc.issuer.id, testIssuer.id);
        expect(parsedVc.validFrom, testValidFrom);
        expect(parsedVc.validUntil, testValidUntil);
        expect(parsedVc.credentialSubject.id, testCredentialSubject.id);
        expect(parsedVc.credentialSchema.length, 1);
        expect(parsedVc.credentialSchema[0].id, testCredentialSchema[0].id);
        expect(parsedVc.credentialStatus?.id, testCredentialStatus.id);
        expect(parsedVc.holder?.id, testHolder.id);
        expect(parsedVc.proof.length, 1);
        expect(parsedVc.proof[0].type, testProof[0].type);
        expect(parsedVc.proof[0].cryptosuite, testProof[0].cryptosuite);
        expect(parsedVc.refreshService?.id, testRefreshService.id);
        expect(parsedVc.termsOfUse.length, 1);
        expect(parsedVc.evidence.length, 1);
      });
    });

    test('fromJson() should handle missing optional fields', () {
      final jsonMap = {
        '@context': testContext,
        'id': testId,
        'type': testType,
        'issuer': testIssuer.toJson(),
        'validFrom': testValidFrom.toIso8601String(),
        'credentialSubject': testCredentialSubject.toJson(),
      };

      final parsedVc = MutableVcDataModelV2.fromJson(jsonMap);

      expect(parsedVc.context, testContext);
      expect(parsedVc.id, testId);
      expect(parsedVc.type, testType);
      expect(parsedVc.issuer.id, testIssuer.id);
      expect(parsedVc.validFrom, testValidFrom);
      expect(parsedVc.validUntil, isNull);
      expect(parsedVc.credentialSubject.id, testCredentialSubject.id);
      expect(parsedVc.credentialSchema, isEmpty);
      expect(parsedVc.credentialStatus, isNull);
      expect(parsedVc.holder, isNull);
      expect(parsedVc.proof, isEmpty);
      expect(parsedVc.refreshService, isNull);
      expect(parsedVc.termsOfUse, isEmpty);
      expect(parsedVc.evidence, isEmpty);
    });

    test('fromJson() should throw error for invalid JSON structure', () {
      final invalidJson = '{"@context": "invalid"}';

      expect(
          () => MutableVcDataModelV2.fromJson(
              invalidJson as Map<String, dynamic>),
          throwsA(isA<TypeError>()));
    });
  });
}
