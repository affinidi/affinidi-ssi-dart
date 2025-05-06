import 'dart:convert';

import '../../linked_data/ld_base_suite.dart';
import '../../models/v2/vc_data_model_v2.dart';
import '../models/parsed_vp.dart';
import '../models/v2/vp_data_model_v2.dart';
import '../suites/vp_suite.dart';

/// Implementation for parsing and processing JSON-LD Verifiable Presentations v2.2.
///
/// Handles the parsing, validation, and processing of W3C Verifiable Presentations
/// following the Data Model v2.2 specification in JSON-LD format.
final class LdVpDm2Suite extends LdBaseSuite<VpDataModelV2, LdVpDataModelV2>
    implements
        VerifiablePresentationSuite<String, VpDataModelV2, LdVpDataModelV2> {
  /// Creates a new [LdVpDm2Suite] with the v2.2 context URL.
  LdVpDm2Suite()
      : super(
            contextUrl: dmV2ContextUrl, issuerKey: VpDataModelV2Key.holder.key);

  /// Parses a [String] input and payload [Map] into a [LdVpDataModelV2] instance.
  @override
  LdVpDataModelV2 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVpDataModelV2.fromParsed(input, payload);
}

/// Implementation of [LdVpDataModelV2] backed by a parsed JSON-LD string.
class LdVpDataModelV2 extends VpDataModelV2
    implements ParsedVerifiablePresentation<String> {
  /// The serialized JSON-LD presentation string.
  final String _serialized;

  /// Creates an instance from a serialized JSON string and parsed input payload.
  ///
  /// The input map is passed to the [MutableVpDataModelV2] constructor, and
  /// the JSON string is parsed for `toJson`.
  LdVpDataModelV2.fromParsed(String serialized, Map<String, dynamic> input)
      : _serialized = serialized,
        // use parsing from VcDataModelV2
        super.clone(VpDataModelV2.fromJson(input));

  /// Returns the JSON representation of the serialized presentation.
  @override
  Map<String, dynamic> toJson() {
    return jsonDecode(_serialized) as Map<String, dynamic>;
  }

  /// Returns the original serialized JSON-LD string.
  @override
  String get serialized => _serialized;
}
