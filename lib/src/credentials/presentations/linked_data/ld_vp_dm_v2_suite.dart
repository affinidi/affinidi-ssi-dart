import '../../linked_data/ld_base_suite.dart';
import '../factories/vp_suite.dart';
import '../models/v2/vp_data_model_v2.dart';
import 'ld_vp_data_model_v2.dart';

class LdVpDm2Options extends LdOptions {}

/// Class to parse and convert a json representation of a [LdVpDataModelV2]
final class LdVpDm2Suite
    extends LdBaseSuite<VpDataModelV2, LdVpDataModelV2, LdVpDm2Options>
    implements
        VerifiablePresentationSuite<String, VpDataModelV2, LdVpDataModelV2,
            LdVpDm2Options> {
  LdVpDm2Suite()
      : super(
          contextUrl: VpDataModelV2.contextUrl,
        );

  @override
  LdVpDataModelV2 fromJson(Map<String, dynamic> payload) =>
      LdVpDataModelV2.fromJson(payload);

  @override
  LdVpDataModelV2 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVpDataModelV2.fromParsed(input, payload);
}
