import 'package:ssi/src/credentials/linked_data/ld_base_suite.dart';
import 'package:ssi/src/credentials/presentations/models/v1/vp_data_model_v1.dart';

import 'ld_vc_data_model_v1.dart';

class LdVcDm1Options extends LdOptions {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVpDm1Suite
    extends LdBaseSuite<VpDataModelV1, LdVpDataModelV1, LdVcDm1Options> {
  @override
  LdVpDataModelV1 fromJson(Map<String, dynamic> input) {
    return LdVpDataModelV1.fromJson(input);
  }

  LdVpDm1Suite()
      : super(
          contextUrl: VpDataModelV1.contextUrl,
        );
}
