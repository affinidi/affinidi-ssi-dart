import '../../../../ssi.dart';
import '../../verification/vc_integrity_verifier.dart';
import '../models/parsed_vp.dart';
import '../suites/vp_suites.dart';
import 'vp_verifier.dart';

/// Global instance of [VcIntegrityVerifier] for credential-level integrity checks.
final vcIntegrityVerifier = VcIntegrityVerifier();

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
  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation data) async {
    final vpSuite = VpSuites.getVpSuite(data);

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
