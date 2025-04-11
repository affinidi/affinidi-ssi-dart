import 'package:ssi/src/credentials/models/v2/vc_data_model_v2_view.dart';

import '../models/v2/vc_data_model_v2.dart';
import '../models/verifiable_credential.dart';
import '../suites/vc_suite.dart';
import 'ld_base_suite.dart';
import 'ld_vc_data_model_v2.dart';

class LdVcDm2Options extends LdOptions {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm2Suite
    extends LdBaseSuite<VcDataModelV2View, LdVcDataModelV2, LdVcDm2Options>
    implements
        VerifiableCredentialSuite<String, VcDataModelV2View, LdVcDataModelV2,
            LdVcDm2Options> {
  LdVcDm2Suite()
      : super(
          contextUrl: VcDataModelV2.contextUrl,
        );

  @override
  LdVcDataModelV2 fromParsed(String input, Map<String, dynamic> payload) =>
      _LdVcDataModelV2Impl.fromParsed(input, payload);
}

class _LdVcDataModelV2Impl extends VcDataModelV2 implements LdVcDataModelV2 {
  final String _serialized;

  _LdVcDataModelV2Impl.fromParsed(String serialized, super.input)
      : _serialized = serialized,
        // use parsing from VcDataModelV1
        super.fromJson();

  @override
  String get serialized => _serialized;
}
