import 'dart:convert';

import '../models/parsed_vc.dart';
import '../models/v2/vc_data_model_v2.dart';
import '../models/verifiable_credential.dart';
import '../suites/vc_suite.dart';
import 'ld_base_suite.dart';

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm2Suite extends LdBaseSuite<VcDataModelV2, LdVcDataModelV2>
    implements
        VerifiableCredentialSuite<String, VcDataModelV2, LdVcDataModelV2> {
  /// Constructs a [LdVcDm2Suite] using the predefined [DMV2ContextUrl].
  LdVcDm2Suite()
      : super(
          contextUrl: DMV2ContextUrl,
        );

  @override
  LdVcDataModelV2 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVcDataModelV2.fromParsed(input, payload);
}

/// A [VcDataModelV2] backed by a parsed JSON-LD serialized string.
///
/// Implements the [ParsedVerifiableCredential] interface.
class LdVcDataModelV2 extends VcDataModelV2
    implements ParsedVerifiableCredential<String> {
  /// The serialized JSON string representation of the credential.
  final String _serialized;

  /// Creates a [LdVcDataModelV2] from a serialized [String] and parsed [input] map.
  LdVcDataModelV2.fromParsed(String serialized, Map<String, dynamic> input)
      : _serialized = serialized,
        super.clone(VcDataModelV2.fromJson(input));

  @override
  Map<String, dynamic> toJson() {
    return jsonDecode(_serialized) as Map<String, dynamic>;
  }

  @override
  String get serialized => _serialized;
}
