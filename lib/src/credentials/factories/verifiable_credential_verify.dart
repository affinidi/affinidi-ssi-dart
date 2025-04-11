import '../../../ssi.dart';
import '../jwt/jwt_dm_v1_suite.dart';
import '../linked_data/ld_dm_v1_suite.dart';
import '../linked_data/ld_dm_v2_suite.dart';
import '../models/parsed_vc.dart';
import '../sdjwt/sdjwt_dm_v2_suite.dart';
import '../verifier/custom_verifier.dart';
import 'vc_suite.dart';

final class CredentialVerifier {
  final List<VerifiableCredentialSuite> suites;
  final List<CustomVerifier> customVerifiers;

  CredentialVerifier({
    List<VerifiableCredentialSuite>? suites,
    List<CustomVerifier>? customVerifier,
  })  : suites = [
          LdVcDm1Suite(),
          LdVcDm2Suite(),
          JwtDm1Suite(),
          SdJwtDm2Suite(),
        ],
        customVerifiers = customVerifier ?? [];

  Future<VerificationResult> verify(ParsedVerifiableCredential data) async {
    final result = VerificationResult.ok();

    final vcSuite = getVcSuit(data.serialized);
    if (vcSuite == null) {
      return VerificationResult.invalid(
          errors: ['No suitable suite found to handle the credential format.']);
    }

    var expiryValid = await vcSuite.verifyExpiry(data);
    if (!expiryValid) {
      result.errors.add('expiry verification failed');
    }

    var integrityValid = await vcSuite.verifyIntegrity(data.serialized);

    if (!integrityValid) {
      result.errors.add('integrity verification failed');
    }

    for (final customVerifier in customVerifiers) {
      var verifResult = await customVerifier.verify(data);
      result.errors.addAll(verifResult.errors);
      result.warnings.addAll(verifResult.warnings);
    }

    return result;
  }

  VerifiableCredentialSuite? getVcSuit(dynamic vc) {
    for (final suite in suites) {
      if (suite.canParse(vc as Object)) {
        return suite;
      }
    }
    return null;
  }
}
