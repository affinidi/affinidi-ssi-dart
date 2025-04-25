import 'dart:convert';

import '../models/parsed_vc.dart';
import '../models/v2/vc_data_model_v2.dart';
import '../models/verifiable_credential.dart';
import '../suites/vc_suite.dart';
import 'ld_base_suite.dart';

class LdVcDm2Options extends LdOptions {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm2Suite
    extends LdBaseSuite<VcDataModelV2, LdVcDataModelV2, LdVcDm2Options>
    implements
        VerifiableCredentialSuite<String, VcDataModelV2, LdVcDataModelV2,
            LdVcDm2Options> {
  LdVcDm2Suite()
      : super(
          contextUrl: VcDataModelV2.contextUrl,
        );

  @override
  LdVcDataModelV2 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVcDataModelV2.fromParsed(input, payload);
}

class LdVcDataModelV2 extends VcDataModelV2
    implements ParsedVerifiableCredential<String> {
  final String _serialized;

  LdVcDataModelV2.fromParsed(String serialized, Map<String, dynamic> input)
      : _serialized = serialized,
        super(VcDataModelV2.fromJson(input));

  @override
  Map<String, dynamic> toJson() {
    return jsonDecode(_serialized) as Map<String, dynamic>;
  }

  @override
  String get serialized => _serialized;
}
