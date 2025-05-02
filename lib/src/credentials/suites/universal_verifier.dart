import '../../types.dart';
import '../models/parsed_vc.dart';
import '../verification/vc_expiry_verifier.dart';
import '../verification/vc_integrity_verifier.dart';
import '../verification/vc_verifier.dart';

/// Allows verification of any supported Verifiable Credential (VC) encodings.
///
/// Combines a default set of verifiers (like expiry and integrity checks)
/// and optional custom verifiers.
final class UniversalVerifier {
  /// List of custom verifiers provided during construction.
  final List<VcVerifier> customVerifiers;

  /// Default verifiers always run during verification.
  ///
  /// Includes:
  /// - [VcExpiryVerifier]: Validates the credential's expiration time.
  /// - [VcIntegrityVerifier]: Validates the cryptographic integrity of the credential.
  static final List<VcVerifier> defaultVerifiers = List.unmodifiable(
    <VcVerifier>[
      VcExpiryVerifier(),
      VcIntegrityVerifier(),
    ],
  );

  /// Creates a [UniversalVerifier].
  ///
  /// Optionally accepts a list of [customVerifiers] to run after the defaults.
  UniversalVerifier({
    List<VcVerifier>? customVerifiers,
  }) : customVerifiers = customVerifiers ?? [];

  /// Verifies the provided [data] using both default and custom verifiers.
  ///
  /// Aggregates all errors and warnings found during verification.
  ///
  /// Returns a [VerificationResult] summarizing the findings.
  Future<VerificationResult> verify(ParsedVerifiableCredential data) async {
    final errors = <String>[];
    final warnings = <String>[];

    for (final verifier in defaultVerifiers) {
      final result = await verifier.verify(data);
      errors.addAll(result.errors);
      warnings.addAll(result.warnings);
    }

    for (final customVerifier in customVerifiers) {
      var verifResult = await customVerifier.verify(data);
      errors.addAll(verifResult.errors);
      warnings.addAll(verifResult.warnings);
    }

    return VerificationResult.fromFindings(
      errors: errors,
      warnings: warnings,
    );
  }
}
