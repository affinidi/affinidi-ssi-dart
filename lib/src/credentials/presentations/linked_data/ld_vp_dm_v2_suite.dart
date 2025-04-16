import 'dart:convert';

import '../../linked_data/ld_base_suite.dart';
import '../models/parsed_vp.dart';
import '../models/v2/vp_data_model_v2.dart';
import '../models/v2/vp_data_model_v2_view.dart';
import '../suites/vp_suite.dart';

/// Options specific to Linked Data VPv2 operations.
class LdVpDm2Options extends LdOptions {}

/// Implementation for parsing and processing JSON-LD Verifiable Presentations v2.2.
///
/// Handles the parsing, validation, and processing of W3C Verifiable Presentations
/// following the Data Model v2.2 specification in JSON-LD format.
final class LdVpDm2Suite
    extends LdBaseSuite<VpDataModelV2, LdVpDataModelV2, LdVpDm2Options>
    implements
        VerifiablePresentationSuite<String, VpDataModelV2, LdVpDataModelV2,
            LdVpDm2Options> {
  /// Creates a new [LdVpDm2Suite] with the v2.2 context URL.
  LdVpDm2Suite()
      : super(
          contextUrl: MutableVpDataModelV2.contextUrl,
        );

  @override
  LdVpDataModelV2 fromParsed(String input, Map<String, dynamic> payload) =>
      _LdVpDataModelV2Impl.fromParsed(input, payload);
}

abstract interface class LdVpDataModelV2
    implements ParsedVerifiablePresentation<String>, VpDataModelV2 {}

class _LdVpDataModelV2Impl extends MutableVpDataModelV2
    implements LdVpDataModelV2 {
  final String _serialized;

  _LdVpDataModelV2Impl.fromParsed(String serialized, super.input)
      : _serialized = serialized,
        // use parsing from VcDataModelV2
        super.fromJson();

  @override
  Map<String, dynamic> toJson() {
    return jsonDecode(_serialized) as Map<String, dynamic>;
  }

  @override
  String get serialized => _serialized;
}
