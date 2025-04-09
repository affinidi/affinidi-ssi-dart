import 'package:ssi/src/credentials/verifier/custom_verifier.dart';
import 'package:ssi/src/credentials/verifier/jwt_vc_data_model_v1_verifier.dart';
import 'package:ssi/src/credentials/verifier/vc_data_model_verifier.dart';
import 'package:ssi/ssi.dart';

final class CredentialVerifier {
  final List<CustomVerifier> customVerifiers;

  CredentialVerifier({
    required this.customVerifiers,
  });

  Future<bool> verify(VerifiableCredential data) async {
    bool result = true;

    final verifier = getVerifier(data);
    bool expiryValid = await verifier.verifyExpiry(data);
    bool integrityValid = await verifier.verifyIntegrity(data);

    result = result && expiryValid;
    result = result && integrityValid;

    for (final customVerifier in customVerifiers) {
      result = result && (await customVerifier.verify(data));
    }

    return result;
  }

  VcDataModelVerifier getVerifier(VerifiableCredential vc) {
    switch (vc.type) {
      case 'any':
        return JwtVcDataModelV1Verifier();
    }
    return JwtVcDataModelV1Verifier();
  }
}
