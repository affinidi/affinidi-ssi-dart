import '../../linked_data/ld_base_suite.dart';
import '../factories/vp_suite.dart';
import '../models/v1/vp_data_model_v1.dart';
import 'ld_vp_data_model_v1.dart';

class LdVpDm1Options extends LdOptions {}

/// Class to parse and convert a json representation of a [LdVpDataModelV1]
final class LdVpDm1Suite
    extends LdBaseSuite<VpDataModelV1, LdVpDataModelV1, LdVpDm1Options>
    implements
        VerifiablePresentationSuite<String, VpDataModelV1, LdVpDataModelV1,
            LdVpDm1Options> {
  LdVpDm1Suite()
      : super(
          contextUrl: VpDataModelV1.contextUrl,
        );

  @override
  LdVpDataModelV1 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVpDataModelV1.fromParsed(input, payload);
}
