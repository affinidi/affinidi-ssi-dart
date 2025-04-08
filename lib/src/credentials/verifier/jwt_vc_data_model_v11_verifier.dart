import 'package:ssi/src/credentials/models/verifiable_credential.dart';
import 'package:ssi/src/credentials/verifier/vc_data_model_verifier.dart';

final class JwtVcDataModelV11Verifier extends VcDataModelVerifier {
  @override
  Future<bool> verifyIntegrity(VerifiableCredential data) {
    // TODO: implement verifyIntegrity
    throw UnimplementedError();
  }
}
