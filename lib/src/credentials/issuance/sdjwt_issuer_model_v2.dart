import '../../did/did_signer.dart';
import '../models/v2/vc_data_model_v2.dart';

class SdJwtIssuerVCModel2 {
  // FIXME iteration 1 we'll only support enveloping proofs for SdJwt, i.e no proof claim inside
  VcDataModelV2 issue({
    required VcDataModelV2 unsignedCredential,
    required DidSigner signer,
  }) {
    return VcDataModelV2();
  }
}
