import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('LD Credential v1 Validation Tests', () {
    test('Throws when context is empty', () {
      final credentialWithEmptyContext = MutableVcDataModelV1(
        context: [],
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithEmptyContext),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when context does not include required URL', () {
      final credentialWithWrongContext = MutableVcDataModelV1(
        context: ['https://www.w3.org/ns/credentials/v2'],
        // Wrong context URL
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithWrongContext),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when type is empty', () {
      final credentialWithEmptyType = MutableVcDataModelV1(
        context: [dmV1ContextUrl],
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithEmptyType),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when type does not include VerifiableCredential', () {
      final credentialWithWrongType = MutableVcDataModelV1(
        context: [dmV1ContextUrl],
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'UniversityDegreeCredential'},
        // Missing VerifiableCredential type
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithWrongType),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when issuer is empty', () {
      final credentialWithEmptyIssuer = MutableVcDataModelV1(
        context: [dmV1ContextUrl],
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri(''),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithEmptyIssuer),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when credentialSubject is empty', () {
      final credentialWithEmptySubject = MutableVcDataModelV1(
        context: [dmV1ContextUrl],
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'VerifiableCredential'},
        credentialSubject: [],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithEmptySubject),
        throwsA(isA<SsiException>()),
      );
    });

    test('Reports multiple validation errors at once', () {
      final credentialWithMultipleErrors = MutableVcDataModelV1(
        context: [],
        issuer: MutableIssuer.uri(''),
        type: {},
        credentialSubject: [],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithMultipleErrors),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when proof has empty id', () {
      final credentialWithEmptyProofId = MutableVcDataModelV1(
        context: [dmV1ContextUrl],
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'VerifiableCredential'},
        issuanceDate: DateTime.now(),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
        proof: [
          EmbeddedProof(
            id: Uri.parse(''), // Empty ID
            type: 'DataIntegrityProof',
            created: DateTime.now(),
            verificationMethod: 'did:example:issuer#key-1',
            proofPurpose: 'assertionMethod',
            proofValue: 'zABC...',
          ),
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithEmptyProofId),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          contains('Proof id cannot be empty'),
        )),
      );
    });

    test('Throws when multiple proofs have duplicate IDs', () {
      final duplicateId = Uri.parse('did:example:proof-1');
      final credentialWithDuplicateProofIds = MutableVcDataModelV1(
        context: [dmV1ContextUrl],
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'VerifiableCredential'},
        issuanceDate: DateTime.now(),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
        proof: [
          EmbeddedProof(
            id: duplicateId,
            type: 'DataIntegrityProof',
            created: DateTime.now(),
            verificationMethod: 'did:example:issuer#key-1',
            proofPurpose: 'assertionMethod',
            proofValue: 'zABC...',
          ),
          EmbeddedProof(
            id: duplicateId, // Duplicate ID
            type: 'EcdsaSecp256k1Signature2019',
            created: DateTime.now(),
            verificationMethod: 'did:example:issuer#key-2',
            proofPurpose: 'assertionMethod',
            proofValue: 'zDEF...',
          ),
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithDuplicateProofIds),
        throwsA(isA<SsiException>().having(
          (e) => e.message,
          'message',
          contains('Duplicate proof id found'),
        )),
      );
    });

    test('Succeeds with unique proof IDs', () {
      final vc = VcDataModelV1(
        context: [dmV1ContextUrl],
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        type: {'VerifiableCredential'},
        issuer: Issuer.uri('did:example:issuer'),
        issuanceDate: DateTime.now(),
        credentialSubject: [
          CredentialSubject.fromJson({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
        proof: [
          EmbeddedProof(
            id: Uri.parse('did:example:proof-1'),
            type: 'DataIntegrityProof',
            created: DateTime.now(),
            verificationMethod: 'did:example:issuer#key-1',
            proofPurpose: 'assertionMethod',
            proofValue: 'zABC...',
          ),
          EmbeddedProof(
            id: Uri.parse('did:example:proof-2'),
            type: 'EcdsaSecp256k1Signature2019',
            created: DateTime.now(),
            verificationMethod: 'did:example:issuer#key-2',
            proofPurpose: 'assertionMethod',
            proofValue: 'zDEF...',
          ),
        ],
      );
      expect(vc.proof.length, 2);
      expect(vc.proof[0].id.toString(), 'did:example:proof-1');
      expect(vc.proof[1].id.toString(), 'did:example:proof-2');
    });

    test('Succeeds when some proofs have IDs and some do not', () {
      final vc = VcDataModelV1(
        context: [dmV1ContextUrl],
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        type: {'VerifiableCredential'},
        issuer: Issuer.uri('did:example:issuer'),
        issuanceDate: DateTime.now(),
        credentialSubject: [
          CredentialSubject.fromJson({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
        proof: [
          EmbeddedProof(
            id: Uri.parse('did:example:proof-1'),
            type: 'DataIntegrityProof',
            created: DateTime.now(),
            verificationMethod: 'did:example:issuer#key-1',
            proofPurpose: 'assertionMethod',
            proofValue: 'zABC...',
          ),
          EmbeddedProof(
            // No ID
            type: 'EcdsaSecp256k1Signature2019',
            created: DateTime.now(),
            verificationMethod: 'did:example:issuer#key-2',
            proofPurpose: 'assertionMethod',
            proofValue: 'zDEF...',
          ),
        ],
      );
      expect(vc.proof.length, 2);
      expect(vc.proof[0].id.toString(), 'did:example:proof-1');
      expect(vc.proof[1].id, isNull);
    });
  });
}
