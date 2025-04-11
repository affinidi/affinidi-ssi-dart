import 'package:ssi/src/credentials/models/parsed_vc.dart';
import 'package:ssi/src/credentials/verification/vc_verifier.dart';
import 'package:ssi/src/types.dart';

import '../../exceptions/ssi_exception_type.dart';
import '../factories/verifiable_credential_parser.dart';

class VcIntegrityVerifier implements VcVerifier {
  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential data) async {
    final vcSuite = VerifiableCredentialParser.getVcSuite(data);

    var integrityValid = await vcSuite.verifyIntegrity(data.serialized);

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
