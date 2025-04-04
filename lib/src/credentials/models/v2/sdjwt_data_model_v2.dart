import 'package:sdjwt/sdjwt.dart';

import 'parsed_vc_data_model_v2.dart';

const String VCV2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
const String SD_JWT_VC_TYPE = 'EnvelopedVerifiableCredential';
const sdjwtVcMimeType = "application/vc+sd-jwt";
const vcIdBegin = "data:$sdjwtVcMimeType,";

class SdjwtDataModelV2 extends ParsedVcDataModelV2 {
  final SdJwt sdJwt;
  SdjwtDataModelV2(this.sdJwt, ParsedVcDataModelV2 vcdm) : super(vcdm.rawData);

  get serialized => sdJwt.serialized;

  get header => sdJwt.header;

  get disclosures => Set.unmodifiable(sdJwt.disclosures);

  @override
  Map<String, dynamic> toJson() {
    return envelope(sdJwt.serialized);
  }

  Map<String, dynamic> envelope(String encoded) {
    return {
      "@context": VCV2_CONTEXT,
      "id": "$vcIdBegin$encoded",
      "type": SD_JWT_VC_TYPE,
    };
  }
}
