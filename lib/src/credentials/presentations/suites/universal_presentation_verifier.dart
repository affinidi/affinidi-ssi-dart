import '../../../types.dart';
import '../../proof/embedded_proof_suite.dart';
import '../../suites/universal_verifier.dart';
import '../../verification/vc_verifier.dart';
import '../models/parsed_vp.dart';
import '../verification/delegation_vc_verifier.dart';
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

  /// The list of vc verifiers
  final List<VcVerifier> credentialCustomVerifiers;

  /// Custom document loader for loading external resources during verification.
  final DocumentLoader? customDocumentLoader;

  /// The default set of verifiers applied to every presentation.
  List<VpVerifier> get defaultVerifiers => List.unmodifiable(
        <VpVerifier>[
          VpExpiryVerifier(),
          VpIntegrityVerifier(customDocumentLoader),
          DelegationVcVerifier(),
        ],
      );

  /// Creates a new [UniversalPresentationVerifier].
  ///
  /// Optionally accepts [customVerifiers] to extend validation logic.
  UniversalPresentationVerifier({
    List<VpVerifier>? customVerifiers,
    List<VcVerifier>? credentialCustomVerifiers,
    this.customDocumentLoader,
  })  : customVerifiers = customVerifiers ?? [],
        credentialCustomVerifiers = credentialCustomVerifiers ?? [];

  /// Verifies the given [ParsedVerifiablePresentation] using all registered verifiers.
  ///
  /// Returns a [VerificationResult] that contains any collected errors and warnings.
  Future<VerificationResult> verify(ParsedVerifiablePresentation vp) async {
    final errors = <String>[];
    final warnings = <String>[];

    for (final verifier in defaultVerifiers) {
      final result = await verifier.verify(vp);
      errors.addAll(result.errors);
      warnings.addAll(result.warnings);
    }

    for (final customVerifier in customVerifiers) {
      var verifResult = await customVerifier.verify(vp);
      errors.addAll(verifResult.errors);
      warnings.addAll(verifResult.warnings);
    }

    final vcVerifier = UniversalVerifier(
        customVerifiers: credentialCustomVerifiers,
        customDocumentLoader: customDocumentLoader);

    for (final credential in vp.verifiableCredential) {
      final vcVerificationResult = await vcVerifier.verify(credential);
      errors.add(vcVerificationResult.errors);
      warnings.add(vcVerificationResult.warnings);
    }

    return VerificationResult.fromFindings(
      errors: errors,
      warnings: warnings,
    );
  }
}
