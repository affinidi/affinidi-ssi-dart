import '../suites/vc_suite.dart';
import '../models/v1/vc_data_model_v1.dart';
import '../models/verifiable_credential.dart';
import 'ld_base_suite.dart';
import 'ld_vc_data_model_v1.dart';

class LdVcDm1Options extends LdOptions {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm1Suite
    extends LdBaseSuite<VcDataModelV1, LdVcDataModelV1, LdVcDm1Options>
    implements
        VerifiableCredentialSuite<String, VcDataModelV1, LdVcDataModelV1,
            LdVcDm1Options> {
  // @override
  // LdVcDataModelV1 fromJson(Map<String, dynamic> input) {
  //   return LdVcDataModelV1.fromJson(input);
  // }

  LdVcDm1Suite()
      : super(
          contextUrl: VcDataModelV1.contextUrl,
        );

  @override
  LdVcDataModelV1 fromJson(Map<String, dynamic> payload) =>
      LdVcDataModelV1.fromJson(payload);

  @override
  LdVcDataModelV1 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVcDataModelV1.fromParsed(input, payload);
}
