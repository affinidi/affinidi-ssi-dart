import 'dart:convert';

import '../models/v1/vc_data_model_v1.dart';
import '../models/v1/vc_data_model_v1_view.dart';
import '../models/verifiable_credential.dart';
import '../suites/vc_suite.dart';
import 'ld_base_suite.dart';
import 'ld_vc_data_model_v1.dart';

class LdVcDm1Options extends LdOptions {
  /// Creates an options object for LdVcDm1Options.
  ///
  /// [embeddedProofSuiteConfig] - Specify suite config for issuance.
  LdVcDm1Options({super.embeddedProofSuiteConfig});
}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm1Suite
    extends LdBaseSuite<VcDataModelV1, LdVcDataModelV1, LdVcDm1Options>
    implements
        VerifiableCredentialSuite<String, VcDataModelV1, LdVcDataModelV1,
            LdVcDm1Options> {
  LdVcDm1Suite()
      : super(
          contextUrl: MutableVcDataModelV1.contextUrl,
        );

  @override
  LdVcDataModelV1 fromParsed(String input, Map<String, dynamic> payload) =>
      _LdVcDataModelV1Impl.fromParsed(input, payload);
}

class _LdVcDataModelV1Impl extends MutableVcDataModelV1
    implements LdVcDataModelV1 {
  final String _serialized;

  _LdVcDataModelV1Impl.fromParsed(String serialized, super.input)
      : _serialized = serialized,
        // use parsing from VcDataModelV1
        super.fromJson();

  @override
  Map<String, dynamic> toJson() {
    return jsonDecode(_serialized) as Map<String, dynamic>;
  }

  @override
  String get serialized => _serialized;
}
