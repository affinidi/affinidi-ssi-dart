import '../../../../ssi.dart';
import '../../verification/vc_integrity_verifier.dart';
import '../models/parsed_vp.dart';
import '../suites/vp_suites.dart';
import 'vp_verifier.dart';

final vcIntegrityVerifier = VcIntegrityVerifier();

class VpIntegrityVerifier implements VpVerifier {
  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation data) async {
    final vpSuite = VpSuites.getVpSuite(data);

    var integrityValid = await vpSuite.verifyIntegrity(data);

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
