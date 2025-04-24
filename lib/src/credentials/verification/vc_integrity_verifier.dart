import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../models/parsed_vc.dart';
import '../suites/vc_suites.dart';
import 'vc_verifier.dart';

class VcIntegrityVerifier implements VcVerifier {
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
