import '../../../../ssi.dart';

/// Verifier that ensures the integrity of both the Verifiable Presentation (VP)
/// and its embedded Verifiable Credentials (VCs).
///
/// This verifier fails fast: it stops at the first encountered integrity issue./// Example:
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

  /// Creates a [VpIntegrityVerifier].
  VpIntegrityVerifier([this.customDocumentLoader]);

  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation data) async {
    final vpSuite =
        VpSuites.getVpSuiteWithDocumentLoader(data, customDocumentLoader);

    var integrityValid = false;

    try {
      integrityValid = await vpSuite.verifyIntegrity(data);
    } catch (e) {
      integrityValid = false;
    }

    if (!integrityValid) {
      return Future.value(
        VerificationResult.invalid(
          errors: [SsiExceptionType.failedIntegrityVerification.code],
        ),
      );
    }
    // Create instance of [VcIntegrityVerifier] for credential-level integrity checks.
    final vcIntegrityVerifier =
        VcIntegrityVerifier(customDocumentLoader: customDocumentLoader);

    for (final credential in data.verifiableCredential) {
      var vcIntegrity = await vcIntegrityVerifier.verify(credential);

      if (!vcIntegrity.isValid) {
        return vcIntegrity;
      }
    }

    return Future.value(
      VerificationResult.ok(),
    );
  }
}
