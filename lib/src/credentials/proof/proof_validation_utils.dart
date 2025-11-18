import '../../types.dart';
import '../proof/proof_purpose.dart';

/// Utility functions for proof validation shared across different verifiers.
class ProofValidationUtils {
  /// Validates that a proof type is not null or empty.
  ///
  /// Returns a [VerificationResult] indicating whether the proof type is valid.
  /// If invalid, returns a result with an appropriate error message.
  ///
  /// Parameters:
  /// - [proofType]: The proof type value to validate (can be any dynamic type)
  ///
  /// Returns:
  /// - [VerificationResult.ok()] if the proof type is a non-empty string
  /// - [VerificationResult.invalid()] with error message if validation fails
  static VerificationResult validateProofType(dynamic proofType) {
    if (proofType == null || (proofType is String && proofType.isEmpty)) {
      return VerificationResult.invalid(
        errors: ['proof type is required and cannot be empty'],
      );
    }
    return VerificationResult.ok();
  }

  /// Validates that a proof type matches the expected type.
  ///
  /// Returns a [VerificationResult] indicating whether the proof type matches.
  ///
  /// Parameters:
  /// - [actualProofType]: The actual proof type value from the proof
  /// - [expectedProofType]: The expected proof type value
  ///
  /// Returns:
  /// - [VerificationResult.ok()] if types match
  /// - [VerificationResult.invalid()] with error message if types don't match
  static VerificationResult validateProofTypeMatch(
    dynamic actualProofType,
    String expectedProofType,
  ) {
    if (actualProofType != expectedProofType) {
      return VerificationResult.invalid(
        errors: ['invalid proof type, expected $expectedProofType'],
      );
    }
    return VerificationResult.ok();
  }

  /// Validates proof structure including type validation and type matching.
  ///
  /// This is a convenience method that combines proof type validation and matching.
  ///
  /// Parameters:
  /// - [proof]: The proof object to validate (should be a Map)
  /// - [expectedProofType]: The expected proof type string
  ///
  /// Returns:
  /// - [VerificationResult.ok()] if all validations pass
  /// - [VerificationResult.invalid()] with error message if any validation fails
  static VerificationResult validateProofTypeStructure(
    Map<String, dynamic> proof,
    String expectedProofType,
  ) {
    final proofType = proof['type'];

    final typeValidation = validateProofType(proofType);
    if (!typeValidation.isValid) {
      return typeValidation;
    }

    return validateProofTypeMatch(proofType, expectedProofType);
  }

  /// Validates that the proof purpose matches the expected purpose based on document type.
  ///
  /// Parameters:
  /// - [proofPurpose]: The proof purpose value to validate (should be a String)
  /// - [docType]: The type of the document containing the proof (can be String or List)
  ///
  /// Returns:
  /// - [VerificationResult.ok()] if the proof purpose matches the expected purpose
  /// - [VerificationResult.invalid()] with error message if the proof purpose does not match
  static VerificationResult validateProofPurpose(
      String proofPurpose, dynamic docType) {
    final expectedProofPurpose =
        (docType is List && docType.contains('VerifiablePresentation') ||
                docType is String && docType == 'VerifiablePresentation')
            ? ProofPurpose.authentication.value
            : ProofPurpose.assertionMethod.value;

    if (proofPurpose != expectedProofPurpose) {
      return VerificationResult.invalid(
        errors: ['invalid proof purpose, expected $expectedProofPurpose'],
      );
    }
    return VerificationResult.ok();
  }
}
