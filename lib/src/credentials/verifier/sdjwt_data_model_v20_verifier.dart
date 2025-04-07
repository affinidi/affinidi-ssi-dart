import 'package:ssi/src/credentials/models/verifiable_credential.dart';
import 'package:ssi/src/credentials/verifier/vc_data_model_verifier.dart';

final class SdjwtDataModelV20Verifier extends VcDataModelVerifier {
  @override
  bool checkIntegrityVerification(VerifiableCredential data) {
    // TODO: implement checkIntegrityVerification
    throw UnimplementedError();
  }
}
