import '../../../../ssi.dart';

/// A verifier that checks whether any of the credentials in a Verifiable Presentation (VP)
/// have expired.
///
/// Delegates verification to [VcExpiryVerifier] for each embedded credential.
///
/// This verifier **fails fast**: it stops on the first expired credential and
/// returns that result.
///
/// Example:
/// ```dart
/// final verifier = VpExpiryVerifier();
/// final result = await verifier.verify(vp);
/// if (!result.isValid) {
///   print("Presentation contains expired credentials");
/// }
/// ```
class VpExpiryVerifier implements VpVerifier {
  final VcExpiryVerifier _vcExpiryVerifier;

  /// Creates a [VpExpiryVerifier].
  VpExpiryVerifier({
    DateTime Function() getNow = DateTime.now,
  }) : _vcExpiryVerifier = VcExpiryVerifier(getNow: getNow);

  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation data) async {
    for (final credential in data.verifiableCredential) {
      final expiryVerification = await _vcExpiryVerifier.verify(credential);

      if (!expiryVerification.isValid) {
        return expiryVerification;
      }
    }

    return Future.value(
      VerificationResult.ok(),
    );
  }
}
