import '../../../types.dart';
import '../models/parsed_vp.dart';
import 'vp_verifier.dart';

/// A verifier that checks the nonce in the proof of a Verifiable Presentation.
///
/// The nonce is used to prevent replay attacks by ensuring the presentation
/// was created in response to a specific challenge.
///
/// **Verification Logic:**
/// - If no expected nonce is provided, verification always passes (nonce is optional)
/// - If an expected nonce is provided:
///   - The proof must contain a nonce field
///   - The proof's nonce must match the expected nonce exactly
///
/// Example:
/// ```dart
///  final nonceVerifier = NonceVerifier(nonce: 'expected-nonce-value');
///  final verifier = UniversalPresentationVerifier(customVerifiers: [nonceVerifier]);
///  final result = await verifier.verify(vp);
///  if (!result.isValid) {
///    print("Presentation nonce verification failed: ${result.errors}");
///  }
/// ```
class NonceVerifier implements VpVerifier {
  /// The expected nonce value to validate against the presentation proof.
  ///
  /// When null, nonce verification is skipped and always passes.
  /// When provided, the presentation proof must contain a matching nonce.
  final String? nonce;

  /// Creates a [NonceVerifier] with an optional expected [nonce] value.
  ///
  /// If [nonce] is null, the verifier will skip nonce validation.
  /// If [nonce] is provided, the presentation proof must contain
  /// a nonce field that exactly matches this value.
  const NonceVerifier({this.nonce});

  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation<dynamic> vp) {
    // If no expected nonce, verification passes
    if (nonce == null) {
      return Future.value(VerificationResult.ok());
    }

    // When expected nonce exists, all proofs must have matching nonce
    for (final proof in vp.proof) {
      final proofNonce = proof.nonce;

      // Proof must contain a nonce when one is expected
      if (proofNonce == null) {
        return Future.value(VerificationResult.invalid(
            errors: ['Nonce is required but not found in proof']));
      }

      // Nonce values must match exactly
      if (proofNonce != nonce) {
        return Future.value(VerificationResult.invalid(errors: [
          'Nonce mismatch: expected "$nonce" but got "$proofNonce"'
        ]));
      }
    }

    // All proofs have valid matching nonce
    return Future.value(VerificationResult.ok());
  }
}
