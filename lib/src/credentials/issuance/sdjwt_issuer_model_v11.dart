import '../../did/did_signer.dart';
import '../models/v2/vc_data_model_v20.dart';

class SdJwtIssuerVCModel2 {
  // FIXME iteration 1 we'll only support enveloping proofs for SdJwt, i.e no proof claim inside
  VcDataModelV20 issue({
    required VcDataModelV20 unsignedCredential,
    required DidSigner signer,
  }) {
    return VcDataModelV20();
  }
}
