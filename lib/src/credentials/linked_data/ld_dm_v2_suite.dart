import '../suites/vc_suite.dart';
import '../models/v2/vc_data_model_v2.dart';
import '../models/verifiable_credential.dart';
import 'ld_base_suite.dart';
import 'ld_vc_data_model_v2.dart';

class LdVcDm2Options extends LdOptions {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm2Suite
    extends LdBaseSuite<VcDataModelV2, LdVcDataModelV2, LdVcDm2Options>
    implements
        VerifiableCredentialSuite<String, LdVcDataModelV2, LdVcDataModelV2,
            LdVcDm2Options> {
  LdVcDm2Suite()
      : super(
          contextUrl: VcDataModelV2.contextUrl,
        );

  @override
  LdVcDataModelV2 fromJson(Map<String, dynamic> payload) =>
      LdVcDataModelV2.fromJson(payload);

  @override
  LdVcDataModelV2 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVcDataModelV2.fromParsed(input, payload);
}
