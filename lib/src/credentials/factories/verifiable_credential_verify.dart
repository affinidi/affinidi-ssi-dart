import 'package:ssi/src/credentials/factories/vc_suite.dart';
import 'package:ssi/src/credentials/jwt/jwt_dm_v1_suite.dart';
import 'package:ssi/src/credentials/linked_data/ld_dm_v1_suite.dart';
import 'package:ssi/src/credentials/models/parsed_vc.dart';
import 'package:ssi/src/credentials/sdjwt/sdjwt_dm_v2_suite.dart';
import 'package:ssi/src/credentials/verifier/custom_verifier.dart';
import 'package:ssi/ssi.dart';

final class CredentialVerifier {
  final List<VerifiableCredentialSuite> suites;
  final List<CustomVerifier> customVerifiers;

  CredentialVerifier({
    List<VerifiableCredentialSuite>? suites,
    List<CustomVerifier>? customVerifier,
  })  : suites = [LdVcDm1Suite(), JwtDm1Suite(), SdJwtDm2Suite()],
        customVerifiers = customVerifier ?? [];

  Future<VerificationResult> verify(ParsedVerifiableCredential data) async {
    final result = VerificationResult.ok();

    final vcSuite = getVcSuit(data.serialized);
    if (vcSuite == null) {
      return VerificationResult.invalid(
          errors: ['No suitable suite found to handle the credential format.']);
    }

    bool expiryValid = await vcSuite.verifyExpiry(data);
    if (!expiryValid) {
      result.errors.add('expiry verification failed');
    }

    bool integrityValid = await vcSuite.verifyIntegrity(data.serialized);

    if (!integrityValid) {
      result.errors.add('integrity verification failed');
    }

    for (final customVerifier in customVerifiers) {
      var verifResult = (await customVerifier.verify(data));
      result.errors.addAll(verifResult.errors);
      result.warnings.addAll(verifResult.warnings);
    }

    return result;
  }

  VerifiableCredentialSuite? getVcSuit(Object vc) {
    for (final suite in suites) {
      if (suite.canParse(vc)) {
        return suite;
      }
    }
    return null;
  }
}
