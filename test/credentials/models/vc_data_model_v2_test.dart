import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('VcDataModelV2 Tests', () {
    test('should correctly assign context', () {
      final ctx = MutableJsonLdContext.fromJson(
          [dmV2ContextUrl, 'https://example.org/context/v2']);
      final vc = MutableVcDataModelV2(
          context: ctx,
          id: Uri.parse('http://example.edu/credentials/abcde'),
          type: {'VerifiableCredential', 'ExampleCredentialV2'},
          issuer: Issuer.uri('did:example:issuerV2'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subjectV2',
              'email': 'user@affinidi.com',
            }),
          ]);
      expect(vc.context, ctx);
    });

    test('should correctly assign id', () {
      final id = Uri.parse('http://example.edu/credentials/abcde');
      final vc = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: id,
        type: {'VerifiableCredential'},
        issuer: Issuer.uri('did:example:issuerV2'),
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subjectV2'})
        ],
      );
      expect(vc.id, id);
    });

    test('should correctly assign type', () {
      final type = {'VerifiableCredential', 'ExampleCredentialV2'};
      final vc = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('id'),
        type: type,
        issuer: Issuer.uri('did:example:issuerV2'),
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subjectV2'})
        ],
      );
      expect(vc.type, type);
    });

    test('should correctly assign issuer', () {
      final issuer = Issuer.uri('did:example:issuerV2');
      final vc = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('id'),
        type: {'t'},
        issuer: issuer,
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subjectV2'})
        ],
      );
      expect(vc.issuer, issuer);
      expect(vc.issuer?.id, issuer.id);
    });

    test('should correctly assign validFrom', () {
      final vf = DateTime.utc(2024, 01, 01, 12, 0, 0);
      final vc = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('id'),
        type: {'t'},
        issuer: Issuer.uri('did:example:issuerV2'),
        validFrom: vf,
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subjectV2'})
        ],
      );
      expect(vc.validFrom, vf);
    });

    test('should correctly assign validUntil', () {
      final vu = DateTime.utc(2025, 01, 01, 12, 0, 0);
      final vc = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('id'),
        type: {'t'},
        issuer: Issuer.uri('did:example:issuerV2'),
        validUntil: vu,
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subjectV2'})
        ],
      );
      expect(vc.validUntil, vu);
    });

    test('should correctly assign credentialSubject', () {
      final subject = MutableCredentialSubject({
        'id': 'did:example:subjectV2',
        'email': 'user@affinidi.com',
      });

      final vc = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('id'),
        type: {'t'},
        issuer: Issuer.uri('did:example:issuerV2'),
        credentialSubject: [subject],
      );
      expect(vc.credentialSubject.first, subject);
      expect(vc.credentialSubject.first.id, subject.id);
      expect(vc.credentialSubject.first['name'], subject['name']);
      expect(vc.credentialSubject.first['role'], subject['role']);
    });

    test('should correctly assign credentialSchema', () {
      final schema = [
        MutableCredentialSchema.build(
            domain: 'https://example.org/schemas/v2',
            schema: 'example',
            type: 'JsonSchemaValidator2018'),
        MutableCredentialSchema.build(
            domain: 'https://example.org/schemas/v2',
            schema: 'another',
            type: 'AnotherSchemaValidator'),
      ];
      final vc = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('id'),
        type: {'t'},
        issuer: Issuer.uri('did:example:issuerV2'),
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subjectV2'})
        ],
        credentialSchema: schema,
      );
      expect(vc.credentialSchema, schema);
      expect(vc.credentialSchema.length, 2);
    });

    test('should correctly assign credentialStatus', () {
      final status = MutableCredentialStatusV2({
        'id': Uri.parse('https://example.edu/status/v2/1'),
        'type': 'CredentialStatusList2021',
      });
      final vc = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('id'),
        type: {'t'},
        issuer: Issuer.uri('did:example:issuerV2'),
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subjectV2'})
        ],
        credentialStatus: [status],
      );
      expect(vc.credentialStatus.first, status);
      expect(vc.credentialStatus.first.id, status.id);
      expect(vc.credentialStatus.first.type, status.type);
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
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('id'),
        type: {'t'},
        issuer: Issuer.uri('did:example:issuerV2'),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subjectV2',
          })
        ],
        proof: proofs,
      );
      expect(vc.proof, proofs);
      expect(vc.proof.length, 2);
      expect(vc.proof.first.type, proofs.first.type);
      expect(vc.proof.last.type, proofs.last.type);
    });

    test('should correctly assign refreshService', () {
      final rs = MutableRefreshServiceV2(
        type: 'ManualRefreshService2021',
      );
      final vc = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('id'),
        type: {'t'},
        issuer: Issuer.uri('did:example:issuerV2'),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subjectV2',
          })
        ],
        refreshService: [rs],
      );
      expect(vc.refreshService.first, rs);
      expect(vc.refreshService.first.type, rs.type);
    });

    test('should correctly assign termsOfUse', () {
      final terms = [
        MutableTermsOfUse(
          id: Uri.parse('https://example.com/tos/v2/1'),
          type: 'IssuerPolicyV2',
        ),
        MutableTermsOfUse(type: 'AnotherTermV2'),
      ];
      final vc = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('id'),
        type: {'t'},
        issuer: Issuer.uri('did:example:issuerV2'),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subjectV2',
          })
        ],
        termsOfUse: terms,
      );
      expect(vc.termsOfUse, terms);
      expect(vc.termsOfUse.length, 2);
    });

    test('should correctly assign evidence', () {
      final evidences = [
        MutableEvidence(
          id: Uri.parse('https://example.edu/evidence/v2/1'),
          type: 'DocumentVerificationV2',
        ),
        MutableEvidence(type: 'AnotherEvidenceV2'),
      ];
      final vc = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('id'),
        type: {'t'},
        issuer: Issuer.uri('did:example:issuerV2'),
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subjectV2'})
        ],
        evidence: evidences,
      );
      expect(vc.evidence, evidences);
      expect(vc.evidence.length, 2);
    });

    test('toJson() should produce correct map (multiple proofs)', () {
      final ctx = MutableJsonLdContext.fromJson([dmV2ContextUrl, 'https://example.org/context/v2']);
      final id = Uri.parse('http://example.edu/credentials/abcde');
      final type = ['VerifiableCredential', 'ExampleCredentialV2'];
      final issuer = Issuer.uri('did:example:issuerV2');
      final vf = DateTime.utc(2024, 01, 01, 12, 0, 0);
      final vu = DateTime.utc(2025, 01, 01, 12, 0, 0);
      final subject = [
        MutableCredentialSubject(
            {'id': 'did:example:subjectV2', 'email': 'user@affinidi.com'})
      ];
      final schema = [
        MutableCredentialSchema.build(
            domain: 'https://example.org/schemas/v2',
            schema: 'example',
            type: 'JsonSchemaValidator2018'),
        MutableCredentialSchema.build(
            domain: 'https://example.org/schemas/v2',
            schema: 'another',
            type: 'AnotherSchemaValidator'),
      ];
      final status = MutableCredentialStatusV2({
        'id': Uri.parse('https://example.edu/status/v2/1'),
        'type': 'CredentialStatusList2021'
      });
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
      final rs = MutableRefreshServiceV2(type: 'ManualRefreshService2021');
      final terms = [
        MutableTermsOfUse(
            id: Uri.parse('https://example.com/tos/v2/1'),
            type: 'IssuerPolicyV2'),
        MutableTermsOfUse(type: 'AnotherTermV2')
      ];
      final evidences = [
        MutableEvidence(
            id: Uri.parse('https://example.edu/evidence/v2/1'),
            type: 'DocumentVerificationV2'),
        MutableEvidence(type: 'AnotherEvidenceV2')
      ];
      final vc = MutableVcDataModelV2(
        context: ctx,
        id: id,
        type: type.toSet(),
        issuer: issuer,
        validFrom: vf,
        validUntil: vu,
        credentialSubject: subject,
        credentialSchema: schema,
        credentialStatus: [status],
        proof: proofs,
        refreshService: [rs],
        termsOfUse: terms,
        evidence: evidences,
      );
      final map = vc.toJson();
      expect(map['@context'], ctx.uris.map((u) => u.toString()).toList());
      expect(map['id'], id.toString());
      expect(map['type'], type);
      expect(map['issuer'], issuer.toJson());
      expect(map['validFrom'], vf.toIso8601String());
      expect(map['validUntil'], vu.toIso8601String());
      expect(map['credentialSubject'], subject.first.toJson());
      expect(map['credentialSchema'], schema.map((e) => e.toJson()).toList());
      expect(map['credentialStatus'], status.toJson());
      expect(map['proof'], proofs.map((e) => e.toJson()).toList());
      expect(map['refreshService'], rs.toJson());
      expect(map['termsOfUse'], terms.map((e) => e.toJson()).toList());
      expect(map['evidence'], evidences.map((e) => e.toJson()).toList());
    });

    test('toJson() should produce correct map (single proof)', () {
      final ctx = MutableJsonLdContext.fromJson(
          [dmV2ContextUrl, 'https://example.org/context/v2']);
      final id = Uri.parse('http://example.edu/credentials/abcde');
      final type = ['VerifiableCredential', 'ExampleCredentialV2'];
      final issuer = Issuer.uri('did:example:issuerV2');
      final vf = DateTime.utc(2024, 01, 01, 12, 0, 0);
      final vu = DateTime.utc(2025, 01, 01, 12, 0, 0);
      final subject = [
        MutableCredentialSubject(
            {'id': 'did:example:subjectV2', 'email': 'user@affinidi.com'})
      ];
      final schema = [
        MutableCredentialSchema.build(
            domain: 'https://example.org/schemas/v2',
            schema: 'example',
            type: 'JsonSchemaValidator2018')
      ];
      final status = MutableCredentialStatusV2({
        'id': Uri.parse('https://example.edu/status/v2/1'),
        'type': 'CredentialStatusList2021'
      });
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
      final rs = MutableRefreshServiceV2(type: 'ManualRefreshService2021');
      final terms = [
        MutableTermsOfUse(
            id: Uri.parse('https://example.com/tos/v2/1'),
            type: 'IssuerPolicyV2')
      ];
      final evidences = [
        MutableEvidence(
            id: Uri.parse('https://example.edu/evidence/v2/1'),
            type: 'DocumentVerificationV2')
      ];
      final vc = MutableVcDataModelV2(
        context: ctx,
        id: id,
        type: type.toSet(),
        issuer: issuer,
        validFrom: vf,
        validUntil: vu,
        credentialSubject: subject,
        credentialSchema: schema,
        credentialStatus: [status],
        proof: proof,
        refreshService: [rs],
        termsOfUse: terms,
        evidence: evidences,
      );
      final map = vc.toJson();
      expect(map['@context'], ctx.uris.map((u) => u.toString()).toList());
      expect(map['id'], id.toString());
      expect(map['type'], type);
      expect(map['issuer'], issuer.toJson());
      expect(map['validFrom'], vf.toIso8601String());
      expect(map['validUntil'], vu.toIso8601String());
      expect(map['credentialSubject'], subject.first.toJson());
      expect(map['credentialSchema'], schema.first.toJson());
      expect(map['credentialStatus'], status.toJson());
      expect(map['proof'], proof.first.toJson());
      expect(map['refreshService'], rs.toJson());
      expect(map['termsOfUse'], terms.first.toJson());
      expect(map['evidence'], evidences.first.toJson());
    });

    test('fromJson() should correctly parse map (multiple proofs)', () {
      final ctx = MutableJsonLdContext.fromJson([dmV2ContextUrl]);
      final vcOriginal = MutableVcDataModelV2(
        context: ctx,
        id: Uri.parse('id'),
        type: {'t'},
        issuer: Issuer.uri('did:example:issuerV2'),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subjectV2',
          })
        ],
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

      final parsed = VcDataModelV2.fromJson(map);
      expect(parsed.context.uris, ctx.uris);
      expect(parsed.id.toString(), 'id');
      expect(parsed.type, ['t']);
      expect(parsed.proof.length, 2);
      expect(parsed.proof[0].type, vcOriginal.proof[0].type);
      expect(parsed.proof[0].cryptosuite, vcOriginal.proof[0].cryptosuite);
      expect(parsed.proof[1].type, vcOriginal.proof[1].type);
      expect(parsed.proof[1].cryptosuite, vcOriginal.proof[1].cryptosuite);
    });

    test('fromJson() should correctly parse map (single proof object)', () {
      final ctx = MutableJsonLdContext.fromJson([dmV2ContextUrl]);
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
        id: Uri.parse('id'),
        type: {'t'},
        issuer: Issuer.uri('did:example:issuerV2'),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subjectV2',
          })
        ],
        proof: proof,
      );
      final map = vcOriginal.toJson();
      final parsed = VcDataModelV2.fromJson(map);
      expect(parsed.context.uris, ctx.uris);
      expect(parsed.id.toString(), 'id');
      expect(parsed.proof.length, 1);
      expect(parsed.proof.first.type, proof.first.type);
      expect(parsed.proof.first.cryptosuite, proof.first.cryptosuite);
    });

    test('fromJson() should handle missing optional fields', () {
      final ctx = [dmV2ContextUrl];
      final map = {
        '@context': ctx,
        'id': 'id',
        'type': ['t'],
        'issuer': {'id': 'did:example:issuerV2'},
        'validFrom': DateTime.utc(2024, 01, 01).toIso8601String(),
        'credentialSubject': {'id': 'did:example:subjectV2'}
      };
      final parsed = VcDataModelV2.fromJson(map);
      expect([parsed.context.uris.first.toString()], ctx);
      expect(parsed.id.toString(), 'id');
      expect(parsed.validUntil, isNull);
      expect(parsed.credentialSchema, isEmpty);
      expect(parsed.credentialStatus, isEmpty);
      expect(parsed.proof, isEmpty);
      expect(parsed.refreshService, isEmpty);
      expect(parsed.termsOfUse, isEmpty);
      expect(parsed.evidence, isEmpty);
    });

    test('fromJson() should throw error for invalid JSON structure', () {
      final invalidJson = '{"@context": "invalid"}';
      expect(() => VcDataModelV2.fromJson(invalidJson as Map<String, dynamic>),
          throwsA(isA<TypeError>()));
    });
  });
}
