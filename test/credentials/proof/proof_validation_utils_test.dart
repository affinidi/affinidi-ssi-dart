import 'package:ssi/src/credentials/proof/proof_validation_utils.dart';
import 'package:ssi/src/types.dart';
import 'package:test/test.dart';

void main() {
  group('ProofValidationUtils', () {
    group('validateProofType', () {
      test('should pass for valid non-empty string', () {
        final result =
            ProofValidationUtils.validateProofType('DataIntegrityProof');

        expect(result.isValid, true);
        expect(result.errors, isEmpty);
      });

      test('should fail for null proof type', () {
        final result = ProofValidationUtils.validateProofType(null);

        expect(result.isValid, false);
        expect(
          result.errors,
          contains('proof type is required and cannot be empty'),
        );
      });

      test('should fail for empty string proof type', () {
        final result = ProofValidationUtils.validateProofType('');

        expect(result.isValid, false);
        expect(
          result.errors,
          contains('proof type is required and cannot be empty'),
        );
      });

      test('should pass for whitespace string (not empty)', () {
        final result = ProofValidationUtils.validateProofType(' ');

        expect(result.isValid, true);
        expect(result.errors, isEmpty);
      });

      test('should pass for non-string types (validated elsewhere)', () {
        // The function allows non-string types - they fail the isEmpty check
        final result = ProofValidationUtils.validateProofType(123);

        expect(result.isValid, true);
      });
    });

    group('validateProofTypeMatch', () {
      test('should pass when types match exactly', () {
        final result = ProofValidationUtils.validateProofTypeMatch(
          'DataIntegrityProof',
          'DataIntegrityProof',
        );

        expect(result.isValid, true);
        expect(result.errors, isEmpty);
      });

      test('should fail when types do not match', () {
        final result = ProofValidationUtils.validateProofTypeMatch(
          'EcdsaSecp256k1Signature2019',
          'DataIntegrityProof',
        );

        expect(result.isValid, false);
        expect(
          result.errors,
          contains('invalid proof type, expected DataIntegrityProof'),
        );
      });

      test('should fail when actual is null', () {
        final result = ProofValidationUtils.validateProofTypeMatch(
          null,
          'DataIntegrityProof',
        );

        expect(result.isValid, false);
        expect(
          result.errors,
          contains('invalid proof type, expected DataIntegrityProof'),
        );
      });

      test('should be case-sensitive', () {
        final result = ProofValidationUtils.validateProofTypeMatch(
          'dataIntegrityProof', // lowercase
          'DataIntegrityProof',
        );

        expect(result.isValid, false);
      });
    });

    group('validateProofTypeStructure', () {
      test('should pass for valid proof with correct type', () {
        final proof = {
          'type': 'DataIntegrityProof',
          'cryptosuite': 'ecdsa-rdfc-2019',
          'proofValue': 'z123',
        };

        final result = ProofValidationUtils.validateProofTypeStructure(
          proof,
          'DataIntegrityProof',
        );

        expect(result.isValid, true);
        expect(result.errors, isEmpty);
      });

      test('should fail when proof type is missing', () {
        final proof = {
          'cryptosuite': 'ecdsa-rdfc-2019',
          'proofValue': 'z123',
        };

        final result = ProofValidationUtils.validateProofTypeStructure(
          proof,
          'DataIntegrityProof',
        );

        expect(result.isValid, false);
        expect(
          result.errors,
          contains('proof type is required and cannot be empty'),
        );
      });

      test('should fail when proof type is empty', () {
        final proof = {
          'type': '',
          'cryptosuite': 'ecdsa-rdfc-2019',
          'proofValue': 'z123',
        };

        final result = ProofValidationUtils.validateProofTypeStructure(
          proof,
          'DataIntegrityProof',
        );

        expect(result.isValid, false);
        expect(
          result.errors,
          contains('proof type is required and cannot be empty'),
        );
      });

      test('should fail when proof type does not match expected', () {
        final proof = {
          'type': 'EcdsaSecp256k1Signature2019',
          'jws': 'ey...',
        };

        final result = ProofValidationUtils.validateProofTypeStructure(
          proof,
          'DataIntegrityProof',
        );

        expect(result.isValid, false);
        expect(
          result.errors,
          contains('invalid proof type, expected DataIntegrityProof'),
        );
      });

      test('should validate multiple proof types correctly', () {
        final proofs = [
          {
            'type': 'DataIntegrityProof',
            'expected': 'DataIntegrityProof',
            'shouldPass': true
          },
          {
            'type': 'EcdsaSecp256k1Signature2019',
            'expected': 'EcdsaSecp256k1Signature2019',
            'shouldPass': true
          },
          {
            'type': 'Ed25519Signature2020',
            'expected': 'Ed25519Signature2020',
            'shouldPass': true
          },
          {'type': '', 'expected': 'DataIntegrityProof', 'shouldPass': false},
          {
            'type': 'WrongType',
            'expected': 'DataIntegrityProof',
            'shouldPass': false
          },
        ];

        for (final testCase in proofs) {
          final proof = {'type': testCase['type']};
          final result = ProofValidationUtils.validateProofTypeStructure(
            proof,
            testCase['expected'] as String,
          );

          expect(
            result.isValid,
            testCase['shouldPass'],
            reason:
                'Failed for type: ${testCase['type']}, expected: ${testCase['expected']}',
          );
        }
      });
    });

    group('validateProofPurpose', () {
      test('should pass for VerifiableCredential with assertionMethod', () {
        final result = ProofValidationUtils.validateProofPurpose(
          'assertionMethod',
          'VerifiableCredential',
        );

        expect(result.isValid, true);
        expect(result.errors, isEmpty);
      });

      test('should pass for VerifiablePresentation with authentication', () {
        final result = ProofValidationUtils.validateProofPurpose(
          'authentication',
          'VerifiablePresentation',
        );

        expect(result.isValid, true);
        expect(result.errors, isEmpty);
      });

      test('should pass for VerifiableCredential list with assertionMethod',
          () {
        final result = ProofValidationUtils.validateProofPurpose(
          'assertionMethod',
          ['VerifiableCredential', 'CustomCredential'],
        );

        expect(result.isValid, true);
        expect(result.errors, isEmpty);
      });

      test('should pass for VerifiablePresentation list with authentication',
          () {
        final result = ProofValidationUtils.validateProofPurpose(
          'authentication',
          ['VerifiablePresentation', 'CustomPresentation'],
        );

        expect(result.isValid, true);
        expect(result.errors, isEmpty);
      });

      test('should fail for VerifiableCredential with wrong proof purpose', () {
        final result = ProofValidationUtils.validateProofPurpose(
          'authentication',
          'VerifiableCredential',
        );

        expect(result.isValid, false);
        expect(
          result.errors,
          contains('invalid proof purpose, expected assertionMethod'),
        );
      });

      test('should fail for VerifiablePresentation with wrong proof purpose',
          () {
        final result = ProofValidationUtils.validateProofPurpose(
          'assertionMethod',
          'VerifiablePresentation',
        );

        expect(result.isValid, false);
        expect(
          result.errors,
          contains('invalid proof purpose, expected authentication'),
        );
      });
    });

    group('Integration with VerificationResult', () {
      test('should return proper VerificationResult structure', () {
        final result = ProofValidationUtils.validateProofType(null);

        expect(result, isA<VerificationResult>());
        expect(result.isValid, isFalse);
        expect(result.errors, isA<List<String>>());
        expect(result.errors.isNotEmpty, true);
        expect(result.warnings, isEmpty);
      });

      test('should chain validations correctly', () {
        final proof = {'type': 'DataIntegrityProof'};

        // First validate the structure
        var result = ProofValidationUtils.validateProofTypeStructure(
          proof,
          'DataIntegrityProof',
        );
        expect(result.isValid, true);

        // If structure is valid, can proceed with other validations
        if (result.isValid) {
          // Simulate additional validation
          result = VerificationResult.ok();
        }

        expect(result.isValid, true);
      });

      test('should chain proof purpose validation correctly', () {
        final document = {
          'type': ['VerifiableCredential'],
          'issuer': 'did:example:issuer',
        };
        final proof = {
          'type': 'DataIntegrityProof',
          'proofPurpose': 'assertionMethod',
        };

        // First validate the structure
        var result = ProofValidationUtils.validateProofTypeStructure(
          proof,
          'DataIntegrityProof',
        );
        expect(result.isValid, true);

        // Then validate proof purpose
        if (result.isValid) {
          result = ProofValidationUtils.validateProofPurpose(
            proof['proofPurpose'] as String,
            document['type'],
          );
        }

        expect(result.isValid, true);
      });
    });
  });
}
