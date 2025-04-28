import 'dart:convert';

import '../models/parsed_vc.dart';
import '../models/v1/vc_data_model_v1.dart';
import '../models/verifiable_credential.dart';
import '../suites/vc_suite.dart';
import 'ld_base_suite.dart';

class LdVcDm1Options extends LdOptions {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm1Suite
    extends LdBaseSuite<VcDataModelV1, LdVcDataModelV1, LdVcDm1Options>
    implements
        VerifiableCredentialSuite<String, VcDataModelV1, LdVcDataModelV1,
            LdVcDm1Options> {
  LdVcDm1Suite()
      : super(
          contextUrl: DMV1ContextUrl,
        );

  @override
  LdVcDataModelV1 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVcDataModelV1.fromParsed(input, payload);
}

class LdVcDataModelV1 extends VcDataModelV1
    implements ParsedVerifiableCredential<String> {
  final String _serialized;

  LdVcDataModelV1.fromParsed(String serialized, Map<String, dynamic> input)
      : _serialized = serialized,
        super.clone(VcDataModelV1.fromJson(input));

  @override
  Map<String, dynamic> toJson() {
    return jsonDecode(_serialized) as Map<String, dynamic>;
  }

  @override
  String get serialized => _serialized;
}
