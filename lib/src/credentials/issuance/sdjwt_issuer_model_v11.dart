import '../../did/did_signer.dart';
import '../models/vc_data_model_v11.dart';
import '../models/vc_data_model_v20.dart';

class LdpVcIssuerVCModel1 {
  VcDataModelV11 issue({
    required VcDataModelV20 unsignedCredential,
    required DidSigner signer,
  }) {
    return VcDataModelV11();
  }
}
