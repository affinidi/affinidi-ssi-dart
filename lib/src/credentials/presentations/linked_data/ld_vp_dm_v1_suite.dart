import 'dart:convert';

import '../../linked_data/ld_base_suite.dart';
import '../models/parsed_vp.dart';
import '../models/v1/vp_data_model_v1.dart';
import '../models/v1/vp_data_model_v1_view.dart';
import '../suites/vp_suite.dart';

/// Options specific to Linked Data VPv1 operations.
class LdVpDm1Options extends LdOptions {}

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
        );

  @override
  LdVpDataModelV1 fromParsed(String input, Map<String, dynamic> payload) =>
      _LdVpDataModelV1Impl.fromParsed(input, payload);
}

abstract interface class LdVpDataModelV1
    implements ParsedVerifiablePresentation<String>, VpDataModelV1 {}

class _LdVpDataModelV1Impl extends MutableVpDataModelV1
    implements LdVpDataModelV1 {
  final String _serialized;

  _LdVpDataModelV1Impl.fromParsed(String serialized, super.input)
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
