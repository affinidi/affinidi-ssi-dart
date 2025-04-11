import 'package:ssi/src/credentials/linked_data/ld_base_suite.dart';
import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';

import '../factories/vc_suite.dart';
import '../models/verifiable_credential.dart';
import 'ld_vc_data_model_v2.dart';

class LdVcDm2Options extends LdOptions {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm2Suite
    extends LdBaseSuite<VcDataModelV2, LdVcDataModelV2, LdVcDm2Options>
    implements
        VerifiableCredentialSuite<String, LdVcDataModelV2, LdVcDataModelV2,
            LdVcDm2Options> {
  @override
  LdVcDataModelV2 fromJson(Map<String, dynamic> input) {
    return LdVcDataModelV2.fromJson(input);
  }

  LdVcDm2Suite()
      : super(
          contextUrl: VcDataModelV2.contextUrl,
        );
}
