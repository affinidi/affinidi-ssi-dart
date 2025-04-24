import 'dart:convert';

import '../../linked_data/ld_base_suite.dart';
import '../models/parsed_vp.dart';
import '../models/v1/vp_data_model_v1.dart';
import '../models/v1/vp_data_model_v1_view.dart';
import '../suites/vp_suite.dart';

/// Options specific to Linked Data VPv1 operations.
class LdVpDm1Options extends LdOptions {
  /// Creates an options object for LdVpDm1Options.
  ///
  /// [expires] - Specify expiry of proof.
  /// [domain] - Specify one or more security domains in which the proof is meant to be used.
  /// [challenge] - Specify challenge for domain in proof.
  /// [proofPurpose] - Specify proofPurpose
  LdVpDm1Options(
      {super.expires, super.domain, super.challenge, super.proofPurpose});
}

/// Implementation for parsing and processing JSON-LD Verifiable Presentations v1.1.
///
/// Handles the parsing, validation, and processing of W3C Verifiable Presentations
/// following the Data Model v1.1 specification in JSON-LD format.
final class LdVpDm1Suite
    extends LdBaseSuite<VpDataModelV1, LdVpDataModelV1, LdVpDm1Options>
    implements
        VerifiablePresentationSuite<String, VpDataModelV1, LdVpDataModelV1,
            LdVpDm1Options> {
  /// Creates a new [LdVpDm1Suite] with the v1.1 context URL.
  LdVpDm1Suite()
      : super(
            contextUrl: MutableVpDataModelV1.contextUrl,
            issuerKey: VpDataModelV1Key.holder.key);

  /// Parses a [String] input and payload [Map] into a [LdVpDataModelV1] instance.
  @override
  LdVpDataModelV1 fromParsed(String input, Map<String, dynamic> payload) =>
      _LdVpDataModelV1Impl.fromParsed(input, payload);
}

/// Interface combining [ParsedVerifiablePresentation] and [VpDataModelV1]
/// for Linked Data Verifiable Presentations.
abstract interface class LdVpDataModelV1
    implements ParsedVerifiablePresentation<String>, VpDataModelV1 {}

/// Implementation of [LdVpDataModelV1] backed by a parsed JSON-LD string.
class _LdVpDataModelV1Impl extends MutableVpDataModelV1
    implements LdVpDataModelV1 {
  /// The serialized JSON-LD presentation string.
  final String _serialized;

  /// Creates an instance from a serialized JSON string and parsed input payload.
  ///
  /// The input map is passed to the [MutableVpDataModelV1] constructor, and
  /// the JSON string is parsed for `toJson`.
  _LdVpDataModelV1Impl.fromParsed(String serialized, super.input)
      : _serialized = serialized,
        // use parsing from VcDataModelV1
        super.fromJson();

  /// Returns the JSON representation of the serialized presentation.
  @override
  Map<String, dynamic> toJson() {
    return jsonDecode(_serialized) as Map<String, dynamic>;
  }

  /// Returns the original serialized JSON-LD string.
  @override
  String get serialized => _serialized;
}
