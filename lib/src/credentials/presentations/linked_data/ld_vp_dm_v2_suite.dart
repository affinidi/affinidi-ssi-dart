import 'package:ssi/src/credentials/linked_data/ld_base_suite.dart';
import 'package:ssi/src/credentials/presentations/linked_data/ld_vp_data_model_v2.dart';
import 'package:ssi/src/credentials/presentations/models/v2/vp_data_model_v2.dart';

class LdVcDm1Options extends LdOptions {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVpDm2Suite
    extends LdBaseSuite<VpDataModelV2, LdVpDataModelV2, LdVcDm1Options> {
  @override
  LdVpDataModelV2 fromJson(Map<String, dynamic> input) {
    return LdVpDataModelV2.fromJson(input);
  }

  LdVpDm2Suite()
      : super(
          contextUrl: VpDataModelV2.contextUrl,
        );
}
