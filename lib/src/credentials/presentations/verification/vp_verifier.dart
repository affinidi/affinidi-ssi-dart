import '../../../../ssi.dart';

/// Interface for verifying Verifiable Presentations (VPs).
///
/// Implementations of [VpVerifier] encapsulate specific validation logic,
/// such as expiry checks and integrity checks.
///
/// Verifiers are typically used by [UniversalPresentationVerifier] to process
/// a [ParsedVerifiablePresentation].
abstract interface class VpVerifier {
  /// Verifies the given [ParsedVerifiablePresentation].
  ///
  /// Returns a [VerificationResult] indicating success, failure,
  /// and any associated warnings or errors.
  Future<VerificationResult> verify(ParsedVerifiablePresentation vp);
}
