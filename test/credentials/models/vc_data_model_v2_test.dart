import 'package:ssi/src/credentials/models/credential_schema.dart';
import 'package:ssi/src/credentials/models/credential_status.dart';
import 'package:ssi/src/credentials/models/credential_subject.dart';
import 'package:ssi/src/credentials/models/issuer.dart';
import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'package:ssi/src/credentials/models/vc_models.dart';
import 'package:ssi/src/credentials/proof/embedded_proof.dart';
import 'package:test/test.dart';

void main() {
  group('VcDataModelV2 Tests', () {
    test('should correctly assign context', () {
      final ctx = [
        MutableVcDataModelV2.contextUrl,
        'https://example.org/context/v2'
      ];
      final vc = MutableVcDataModelV2(
        context: ctx,
        id: 'http://example.edu/credentials/abcde',
        type: ['VerifiableCredential', 'ExampleCredentialV2'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject: CredentialSubject(
          id: 'did:example:subjectV2',
          claims: {'email': 'user@affinidi.com'},
        ),
      );
      expect(vc.context, ctx);
    });

    test('should correctly assign id', () {
      const id = 'http://example.edu/credentials/abcde';
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: id,
        type: ['VerifiableCredential'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
      );
      expect(vc.id, id);
    });

    test('should correctly assign type', () {
      final type = ['VerifiableCredential', 'ExampleCredentialV2'];
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'id',
        type: type,
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
      );
      expect(vc.type, type);
    });

    test('should correctly assign issuer', () {
      final issuer = Issuer(id: 'did:example:issuerV2');
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'id',
        type: ['t'],
        issuer: issuer,
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
      );
      expect(vc.issuer, issuer);
      expect(vc.issuer.id, issuer.id);
    });

    test('should correctly assign validFrom', () {
      final vf = DateTime.utc(2024, 01, 01, 12, 0, 0);
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'id',
        type: ['t'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        validFrom: vf,
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
      );
      expect(vc.validFrom, vf);
    });

    test('should correctly assign validUntil', () {
      final vu = DateTime.utc(2025, 01, 01, 12, 0, 0);
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'id',
        type: ['t'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        validUntil: vu,
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
      );
      expect(vc.validUntil, vu);
    });

    test('should correctly assign credentialSubject', () {
      final subject = CredentialSubject(
        id: 'did:example:subjectV2',
        claims: {'email': 'user@affinidi.com'},
      );
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'id',
        type: ['t'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject: subject,
      );
      expect(vc.credentialSubject, subject);
      expect(vc.credentialSubject.id, subject.id);
      expect(vc.credentialSubject['name'], subject['name']);
      expect(vc.credentialSubject['role'], subject['role']);
    });

    test('should correctly assign credentialSchema', () {
      final schema = [
        CredentialSchema(
            domain: 'https://example.org/schemas/v2',
            schema: 'example',
            type: 'JsonSchemaValidator2018'),
        CredentialSchema(
            domain: 'https://example.org/schemas/v2',
            schema: 'another',
            type: 'AnotherSchemaValidator'),
      ];
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'id',
        type: ['t'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
        credentialSchema: schema,
      );
      expect(vc.credentialSchema, schema);
      expect(vc.credentialSchema.length, 2);
    });

    test('should correctly assign credentialStatus', () {
      final status = CredentialStatus(
        id: Uri.parse('https://example.edu/status/v2/1'),
        type: 'CredentialStatusList2021',
      );
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'id',
        type: ['t'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
        credentialStatus: status,
      );
      expect(vc.credentialStatus, status);
      expect(vc.credentialStatus?.id, status.id);
      expect(vc.credentialStatus?.type, status.type);
    });

    test('should correctly assign proof', () {
      final proofs = [
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
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'id',
        type: ['t'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
        proof: proofs,
      );
      expect(vc.proof, proofs);
      expect(vc.proof.length, 2);
      expect(vc.proof.first.type, proofs.first.type);
      expect(vc.proof.last.type, proofs.last.type);
    });

    test('should correctly assign refreshService', () {
      final rs = RefreshService(
        id: 'https://example.edu/refresh/v2/1',
        type: 'ManualRefreshService2021',
      );
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'id',
        type: ['t'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
        refreshService: rs,
      );
      expect(vc.refreshService, rs);
      expect(vc.refreshService?.id, rs.id);
      expect(vc.refreshService?.type, rs.type);
    });

    test('should correctly assign termsOfUse', () {
      final terms = [
        TermOfUse(
          id: 'https://example.com/tos/v2/1',
          type: 'IssuerPolicyV2',
        ),
        TermOfUse(type: 'AnotherTermV2'),
      ];
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'id',
        type: ['t'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
        termsOfUse: terms,
      );
      expect(vc.termsOfUse, terms);
      expect(vc.termsOfUse.length, 2);
    });

    test('should correctly assign evidence', () {
      final evidences = [
        Evidence(
          id: 'https://example.edu/evidence/v2/1',
          type: 'DocumentVerificationV2',
        ),
        Evidence(type: 'AnotherEvidenceV2'),
      ];
      final vc = MutableVcDataModelV2(
        context: [MutableVcDataModelV2.contextUrl],
        id: 'id',
        type: ['t'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
        evidence: evidences,
      );
      expect(vc.evidence, evidences);
      expect(vc.evidence.length, 2);
    });

    test('toJson() should produce correct map (multiple proofs)', () {
      final ctx = [
        MutableVcDataModelV2.contextUrl,
        'https://example.org/context/v2'
      ];
      const id = 'http://example.edu/credentials/abcde';
      final type = ['VerifiableCredential', 'ExampleCredentialV2'];
      final issuer = Issuer(id: 'did:example:issuerV2');
      final vf = DateTime.utc(2024, 01, 01, 12, 0, 0);
      final vu = DateTime.utc(2025, 01, 01, 12, 0, 0);
      final subject = CredentialSubject(
          id: 'did:example:subjectV2', claims: {'email': 'user@affinidi.com'});
      final schema = [
        CredentialSchema(
            domain: 'https://example.org/schemas/v2',
            schema: 'example',
            type: 'JsonSchemaValidator2018'),
        CredentialSchema(
            domain: 'https://example.org/schemas/v2',
            schema: 'another',
            type: 'AnotherSchemaValidator'),
      ];
      final status = CredentialStatus(
          id: Uri.parse('https://example.edu/status/v2/1'),
          type: 'CredentialStatusList2021');
      final proofs = [
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
      final rs = RefreshService(
          id: 'https://example.edu/refresh/v2/1',
          type: 'ManualRefreshService2021');
      final terms = [
        TermOfUse(id: 'https://example.com/tos/v2/1', type: 'IssuerPolicyV2'),
        TermOfUse(type: 'AnotherTermV2')
      ];
      final evidences = [
        Evidence(
            id: 'https://example.edu/evidence/v2/1',
            type: 'DocumentVerificationV2'),
        Evidence(type: 'AnotherEvidenceV2')
      ];
      final vc = MutableVcDataModelV2(
        context: ctx,
        id: id,
        type: type,
        issuer: issuer,
        validFrom: vf,
        validUntil: vu,
        credentialSubject: subject,
        credentialSchema: schema,
        credentialStatus: status,
        proof: proofs,
        refreshService: rs,
        termsOfUse: terms,
        evidence: evidences,
      );
      final map = vc.toJson();
      expect(map['@context'], ctx);
      expect(map['id'], id);
      expect(map['type'], type);
      expect(map['issuer'], issuer.toJson());
      expect(map['validFrom'], vf.toIso8601String());
      expect(map['validUntil'], vu.toIso8601String());
      expect(map['credentialSubject'], subject.toJson());
      expect(map['credentialSchema'], schema.map((e) => e.toJson()).toList());
      expect(map['credentialStatus'], status.toJson());
      expect(map['proof'], proofs.map((e) => e.toJson()).toList());
      expect(map['refreshService'], rs.toJson());
      expect(map['termsOfUse'], terms.map((e) => e.toJson()).toList());
      expect(map['evidence'], evidences.map((e) => e.toJson()).toList());
    });

    test('toJson() should produce correct map (single proof)', () {
      final ctx = [
        MutableVcDataModelV2.contextUrl,
        'https://example.org/context/v2'
      ];
      const id = 'http://example.edu/credentials/abcde';
      final type = ['VerifiableCredential', 'ExampleCredentialV2'];
      final issuer = Issuer(id: 'did:example:issuerV2');
      final vf = DateTime.utc(2024, 01, 01, 12, 0, 0);
      final vu = DateTime.utc(2025, 01, 01, 12, 0, 0);
      final subject = CredentialSubject(
          id: 'did:example:subjectV2', claims: {'email': 'user@affinidi.com'});
      final schema = [
        CredentialSchema(
            domain: 'https://example.org/schemas/v2',
            schema: 'example',
            type: 'JsonSchemaValidator2018')
      ];
      final status = CredentialStatus(
          id: Uri.parse('https://example.edu/status/v2/1'),
          type: 'CredentialStatusList2021');
      final proof = [
        EmbeddedProof(
          type: 'DataIntegrityProof',
          created: DateTime.utc(2024, 01, 01, 12, 5, 0),
          verificationMethod: 'did:example:issuerV2#keys-1',
          proofPurpose: 'assertionMethod',
          proofValue: 'zABC...',
          cryptosuite: 'eddsa-jcs-2022',
        )
      ];
      final rs = RefreshService(
          id: 'https://example.edu/refresh/v2/1',
          type: 'ManualRefreshService2021');
      final terms = [
        TermOfUse(id: 'https://example.com/tos/v2/1', type: 'IssuerPolicyV2')
      ];
      final evidences = [
        Evidence(
            id: 'https://example.edu/evidence/v2/1',
            type: 'DocumentVerificationV2')
      ];
      final vc = MutableVcDataModelV2(
        context: ctx,
        id: id,
        type: type,
        issuer: issuer,
        validFrom: vf,
        validUntil: vu,
        credentialSubject: subject,
        credentialSchema: schema,
        credentialStatus: status,
        proof: proof,
        refreshService: rs,
        termsOfUse: terms,
        evidence: evidences,
      );
      final map = vc.toJson();
      expect(map['@context'], ctx);
      expect(map['id'], id);
      expect(map['type'], type);
      expect(map['issuer'], issuer.toJson());
      expect(map['validFrom'], vf.toIso8601String());
      expect(map['validUntil'], vu.toIso8601String());
      expect(map['credentialSubject'], subject.toJson());
      expect(map['credentialSchema'], schema.first.toJson());
      expect(map['credentialStatus'], status.toJson());
      expect(map['proof'], proof.first.toJson());
      expect(map['refreshService'], rs.toJson());
      expect(map['termsOfUse'], terms.first.toJson());
      expect(map['evidence'], evidences.first.toJson());
    });

    test('fromJson() should correctly parse map (multiple proofs)', () {
      final ctx = [MutableVcDataModelV2.contextUrl];
      final vcOriginal = MutableVcDataModelV2(
        context: ctx,
        id: 'id',
        type: ['t'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
        proof: [
          EmbeddedProof(
            type: 'DataIntegrityProof',
            created: DateTime.utc(2024, 01, 01),
            verificationMethod: 'did:example:issuer#1',
            proofPurpose: 'assertionMethod',
            proofValue: 'z',
            cryptosuite: 'eddsa-jcs-2022',
          ),
          EmbeddedProof(
            type: 'AnotherProofType',
            created: DateTime.utc(2024, 01, 02),
            verificationMethod: 'did:example:issuer#2',
            proofPurpose: 'authentication',
            proofValue: 'x',
            cryptosuite: 'ecdsa-jcs-2019',
          ),
        ],
      );
      final map = vcOriginal.toJson();
      final parsed = MutableVcDataModelV2.fromJson(map);
      expect(parsed.context, ctx);
      expect(parsed.id, 'id');
      expect(parsed.type, ['t']);
      expect(parsed.proof.length, 2);
      expect(parsed.proof[0].type, vcOriginal.proof[0].type);
      expect(parsed.proof[0].cryptosuite, vcOriginal.proof[0].cryptosuite);
      expect(parsed.proof[1].type, vcOriginal.proof[1].type);
      expect(parsed.proof[1].cryptosuite, vcOriginal.proof[1].cryptosuite);
    });

    test('fromJson() should correctly parse map (single proof object)', () {
      final ctx = [MutableVcDataModelV2.contextUrl];
      final proof = [
        EmbeddedProof(
          type: 'DataIntegrityProof',
          created: DateTime.utc(2024, 01, 01),
          verificationMethod: 'did:example:issuer#1',
          proofPurpose: 'assertionMethod',
          proofValue: 'z',
          cryptosuite: 'eddsa-jcs-2022',
        )
      ];
      final vcOriginal = MutableVcDataModelV2(
        context: ctx,
        id: 'id',
        type: ['t'],
        issuer: Issuer(id: 'did:example:issuerV2'),
        credentialSubject:
            CredentialSubject(id: 'did:example:subjectV2', claims: {}),
        proof: proof,
      );
      final map = vcOriginal.toJson();
      final parsed = MutableVcDataModelV2.fromJson(map);
      expect(parsed.context, ctx);
      expect(parsed.id, 'id');
      expect(parsed.proof.length, 1);
      expect(parsed.proof.first.type, proof.first.type);
      expect(parsed.proof.first.cryptosuite, proof.first.cryptosuite);
    });

    test('fromJson() should handle missing optional fields', () {
      final ctx = [MutableVcDataModelV2.contextUrl];
      final map = {
        '@context': ctx,
        'id': 'id',
        'type': ['t'],
        'issuer': {'id': 'did:example:issuerV2'},
        'validFrom': DateTime.utc(2024, 01, 01).toIso8601String(),
        'credentialSubject': {'id': 'did:example:subjectV2'}
      };
      final parsed = MutableVcDataModelV2.fromJson(map);
      expect(parsed.context, ctx);
      expect(parsed.id, 'id');
      expect(parsed.validUntil, isNull);
      expect(parsed.credentialSchema, isEmpty);
      expect(parsed.credentialStatus, isNull);
      expect(parsed.proof, isEmpty);
      expect(parsed.refreshService, isNull);
      expect(parsed.termsOfUse, isEmpty);
      expect(parsed.evidence, isEmpty);
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
