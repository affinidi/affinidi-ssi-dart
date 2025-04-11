import '../../../ssi.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../jwt/jwt_data_model_v1.dart';
import '../jwt/jwt_dm_v1_suite.dart';
import '../linked_data/ld_dm_v1_suite.dart';
import '../linked_data/ld_dm_v2_suite.dart';
import '../linked_data/ld_vc_data_model_v1.dart';
import '../linked_data/ld_vc_data_model_v2.dart';
import '../models/parsed_vc.dart';
import '../sdjwt/sd_vc_dm_v2.dart';
import '../sdjwt/sdjwt_dm_v2_suite.dart';
import '../verification/custom_verifier.dart';
import 'vc_suite.dart';

final class CredentialVerifier {
  final List<VerifiableCredentialSuite> suites;
  final List<CustomVerifier> customVerifiers;

  CredentialVerifier({
    List<VerifiableCredentialSuite>? suites,
    List<CustomVerifier>? customVerifier,
  })  : suites = [
          LdVcDm1Suite<void>(),
          LdVcDm2Suite<void>(),
          JwtDm1Suite(),
          SdJwtDm2Suite(),
        ],
        customVerifiers = customVerifier ?? [];

  Future<VerificationResult> verify(ParsedVerifiableCredential data) async {
    final result = VerificationResult.ok();

    final vcSuite = getVcSuit(data);
    if (vcSuite == null) {
      return VerificationResult.invalid(
          errors: [SsiExceptionType.unableToParseVerifiableCredential.code]);
    }

    var expiryValid = await vcSuite.verifyExpiry(data);
    if (!expiryValid) {
      result.errors.add(SsiExceptionType.expiredVC.code);
    }

    var integrityValid = await vcSuite.verifyIntegrity(data.serialized);

    if (!integrityValid) {
      result.errors.add(SsiExceptionType.failedIntegrityVerification.code);
    }

    for (final customVerifier in customVerifiers) {
      var verifResult = await customVerifier.verify(data);
      result.errors.addAll(verifResult.errors);
      result.warnings.addAll(verifResult.warnings);
    }

    return result;
  }

  VerifiableCredentialSuite? getVcSuite(ParsedVerifiableCredential vc) {
    var suit = switch (vc) {
      LdVcDataModelV1() => LdVcDm1Suite<void>() as VerifiableCredentialSuite,
      LdVcDataModelV2() => LdVcDm2Suite<void>() as VerifiableCredentialSuite,
      JwtVcDataModelV1() => JwtDm1Suite() as VerifiableCredentialSuite,
      SdJwtDataModelV2() => SdJwtDm2Suite() as VerifiableCredentialSuite,
      _ => null,
    };

    return suit;
  }
}
