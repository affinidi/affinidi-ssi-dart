import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../models/parsed_vc.dart';
import '../suites/vc_suites.dart';
import 'vc_verifier.dart';

/// Verifier that checks the cryptographic integrity of a Verifiable Credential (VC).
///
/// It delegates the integrity verification to the appropriate VC suite
/// based on the input credentials.
class VcIntegrityVerifier implements VcVerifier {
  /// Verifies the signature and cryptographic integrity of the [data] credential.
  ///
  /// Returns a [VerificationResult] indicating success or reporting a failed
  /// integrity verification error.
  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential data) async {
    final vcSuite = VcSuites.getVcSuite(data);

    var integrityValid = false;

    try {
      integrityValid = await vcSuite.verifyIntegrity(data);
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

    return Future.value(
      VerificationResult.ok(),
    );
  }
}
