import '../../../types.dart';
import '../models/parsed_vp.dart';
import '../verification/vp_expiry_verifier.dart';
import '../verification/vp_integrity_verifier.dart';
import '../verification/vp_verifier.dart';

/// Verifies a [ParsedVerifiablePresentation] using a set of default and custom verifiers.
/// Allows verification of any supported VC encodings.
///
/// Example:
/// ```dart
/// final verifier = UniversalPresentationVerifier(
///   customVerifiers: [MyCustomVpVerifier()],
/// );
/// final result = await verifier.verify(vp);
/// if (result.isValid) {
///   // proceed
/// }
/// ```
final class UniversalPresentationVerifier {
  /// The list of verifiers
  final List<VpVerifier> customVerifiers;

  /// The default set of verifiers applied to every presentation.
  ///
  /// Includes expiry and integrity checks.
  static final List<VpVerifier> defaultVerifiers = List.unmodifiable(
    <VpVerifier>[
      VpExpiryVerifier(),
      VpIntegrityVerifier(),
    ],
  );

  /// Creates a new [UniversalPresentationVerifier].
  ///
  /// Optionally accepts [customVerifiers] to extend validation logic.
  UniversalPresentationVerifier({
    List<VpVerifier>? customVerifiers,
  }) : customVerifiers = customVerifiers ?? [];

  /// Verifies the given [ParsedVerifiablePresentation] using all registered verifiers.
  ///
  /// Returns a [VerificationResult] that contains any collected errors and warnings.
  Future<VerificationResult> verify(ParsedVerifiablePresentation data) async {
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
