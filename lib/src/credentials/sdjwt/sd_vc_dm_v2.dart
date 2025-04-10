import 'package:sdjwt/sdjwt.dart';
import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';

import '../models/parsed_vc.dart';

class SdJwtDataModelV2 extends VcDataModelV2
    implements ParsedVerifiableCredential<String, VcDataModelV2> {
  final SdJwt sdJwt;

  SdJwtDataModelV2({
    required super.context,
    required super.id,
    super.credentialSchema,
    super.credentialSubject,
    required super.issuer,
    required super.type,
    super.validFrom,
    super.validUntil,
    super.holder,
    super.proof,
    super.credentialStatus,
    required this.sdJwt,
  });

  SdJwtDataModelV2.fromSdJwt(this.sdJwt) : super.fromJson(sdJwt.claims);

  @override
  get serialized => sdJwt.serialized;

  get header => sdJwt.header;

  get disclosures => Set.unmodifiable(sdJwt.disclosures);
}
