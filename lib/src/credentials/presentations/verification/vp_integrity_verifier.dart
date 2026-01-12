import '../../../../ssi.dart';

/// Verifier that ensures the integrity of the Verifiable Presentation (VP).
/// [VpIntegrityVerifier] handles VP-level integrity checks only. Use [VcIntegrityVerifier] for individual credential verification within the VP.
/// This verifier fails fast: it stops at the first encountered integrity issue.
/// Example:
/// ```dart
/// final verifier = VpIntegrityVerifier();
/// final result = await verifier.verify(vp);
/// if (!result.isValid) {
///   print("Presentation contains invalid signatures");
/// }
/// ```
class VpIntegrityVerifier implements VpVerifier {
  /// The document loader to use when verifying proofs.
  final DocumentLoader? customDocumentLoader;

  /// Custom DID resolver for resolving DID documents during verification.
  ///
  /// If not provided, the default universal DID resolver is used.
  final DidResolver? didResolver;

  /// Creates a [VpIntegrityVerifier].
  ///
  /// Optionally accepts:
  /// - [customDocumentLoader] to use when loading external resources during verification.
  /// - [didResolver] to use for custom DID resolution logic.
  VpIntegrityVerifier({this.customDocumentLoader, this.didResolver});

  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation data) async {
    final vpSuite =
        VpSuites.getVpSuiteWithDocumentLoader(data, customDocumentLoader);

    var integrityValid = false;

    try {
      integrityValid =
          await vpSuite.verifyIntegrity(data, didResolver: didResolver);
    } catch (e) {
      integrityValid = false;
    }

    if (!integrityValid) {
      return Future.value(
        VerificationResult.invalid(
          errors: [
            '${SsiExceptionType.failedIntegrityVerification.code} for VP id: ${data.id}'
          ],
        ),
      );
    }

    return Future.value(
      VerificationResult.ok(),
    );
  }
}
