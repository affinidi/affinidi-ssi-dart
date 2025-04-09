import 'package:ssi/src/credentials/proof/embedded_proof_suite.dart';
import 'package:ssi/src/credentials/verifier/custom_verifier.dart';
import 'package:ssi/src/credentials/verifier/jwt_vc_data_model_v1_verifier.dart';
import 'package:ssi/src/credentials/verifier/vc_data_model_verifier.dart';
import 'package:ssi/ssi.dart';

final class CredentialVerifier {
  final List<CustomVerifier> customVerifiers;

  CredentialVerifier({
    List<CustomVerifier>? customVerifier,
  }) : customVerifiers = customVerifier ?? [];

  Future<VerificationResult> verify(VerifiableCredential data) async {
    var isValid = true;
    List<String> issues = [];

    final verifier = getVcVerifier(data);
    bool expiryValid = await verifier.verifyExpiry(data);
    bool integrityValid = await verifier.verifyIntegrity(data);

    if (!expiryValid) {
      isValid = false;
      issues.add('expiry verification failed');
    }
    if (!integrityValid) {
      isValid = false;
      issues.add('integrity verification failed');
    }

    for (final customVerifier in customVerifiers) {
      var verifResult = (await customVerifier.verify(data));
      isValid = isValid && verifResult.isValid;
      issues.addAll(verifResult.issues);
    }

    return VerificationResult(isValid: isValid, issues: issues);
  }

  VcDataModelVerifier getVcVerifier(VerifiableCredential vc) {
    //TODO: get verifier based on vc
    switch (vc.type) {
      case 'any':
        return JwtVcDataModelV1Verifier();
    }
    return JwtVcDataModelV1Verifier();
  }
}
