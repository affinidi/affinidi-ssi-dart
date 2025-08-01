import 'dart:convert';

import '../../linked_data/ld_base_suite.dart';
import '../../models/v1/vc_data_model_v1.dart';
import '../models/parsed_vp.dart';
import '../models/v1/vp_data_model_v1.dart';
import '../suites/vp_suite.dart';

/// Implementation for parsing and processing JSON-LD Verifiable Presentations v1.1.
///
/// Handles the parsing, validation, and processing of W3C Verifiable Presentations
/// following the Data Model v1.1 specification in JSON-LD format.
final class LdVpDm1Suite extends LdBaseSuite<VpDataModelV1, LdVpDataModelV1>
    implements
        VerifiablePresentationSuite<String, VpDataModelV1, LdVpDataModelV1> {
  /// Creates a new [LdVpDm1Suite] with the v1.1 context URL.
  LdVpDm1Suite({super.customDocumentLoader})
      : super(
            contextUrl: dmV1ContextUrl, issuerKey: VpDataModelV1Key.holder.key);

  /// Parses a [String] input and payload [Map] into a [LdVpDataModelV1] instance.
  @override
  LdVpDataModelV1 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVpDataModelV1.fromParsed(input, payload);
}

/// Implementation of [LdVpDataModelV1] backed by a parsed JSON-LD string.
class LdVpDataModelV1 extends VpDataModelV1
    implements ParsedVerifiablePresentation<String> {
  /// The serialized JSON-LD presentation string.
  final String _serialized;

  /// Creates an instance from a serialized JSON string and parsed input payload.
  ///
  /// The input map is passed to the [MutableVpDataModelV1] constructor, and
  /// the JSON string is parsed for `toJson`.
  LdVpDataModelV1.fromParsed(String serialized, Map<String, dynamic> input)
      : _serialized = serialized,
        // use parsing from VcDataModelV1
        super.clone(VpDataModelV1.fromJson(input));

  /// Returns the JSON representation of the serialized presentation.
  @override
  Map<String, dynamic> toJson() {
    return jsonDecode(_serialized) as Map<String, dynamic>;
  }

  /// Returns the original serialized JSON-LD string.
  @override
  String get serialized => _serialized;
}
