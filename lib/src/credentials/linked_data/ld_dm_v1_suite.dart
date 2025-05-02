import 'dart:convert';

import '../models/parsed_vc.dart';
import '../models/v1/vc_data_model_v1.dart';
import '../models/verifiable_credential.dart';
import '../suites/vc_suite.dart';
import 'ld_base_suite.dart';

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm1Suite extends LdBaseSuite<VcDataModelV1, LdVcDataModelV1>
    implements
        VerifiableCredentialSuite<String, VcDataModelV1, LdVcDataModelV1> {
  /// Constructs a [LdVcDm1Suite] using the predefined [DMV1ContextUrl].
  LdVcDm1Suite()
      : super(
          contextUrl: DMV1ContextUrl,
        );

  @override
  LdVcDataModelV1 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVcDataModelV1.fromParsed(input, payload);
}

/// A [VcDataModelV1] backed by a parsed JSON-LD serialized string.
///
/// Implements the [ParsedVerifiableCredential] interface.
class LdVcDataModelV1 extends VcDataModelV1
    implements ParsedVerifiableCredential<String> {
  /// The serialized JSON string representation of the credential.
  final String _serialized;

  /// Creates a [LdVcDataModelV1] from a serialized [String] and parsed [input] map.
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
