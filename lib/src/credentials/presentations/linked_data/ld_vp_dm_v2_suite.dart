import '../../linked_data/ld_base_suite.dart';
import '../factories/vp_suite.dart';
import '../models/v2/vp_data_model_v2.dart';
import 'ld_vp_data_model_v2.dart';

/// Options specific to Linked Data VPv2 operations.
class LdVpDm2Options extends LdOptions {}

/// Implementation for parsing and processing JSON-LD Verifiable Presentations v2.0.
///
/// Handles the parsing, validation, and processing of W3C Verifiable Presentations
/// following the Data Model v2.0 specification in JSON-LD format.
final class LdVpDm2Suite
    extends LdBaseSuite<VpDataModelV2, LdVpDataModelV2, LdVpDm2Options>
    implements
        VerifiablePresentationSuite<String, VpDataModelV2, LdVpDataModelV2,
            LdVpDm2Options> {
  /// Creates a new [LdVpDm2Suite] with the v2.0 context URL.
  LdVpDm2Suite()
      : super(
          contextUrl: VpDataModelV2.contextUrl,
        );

  @override
  LdVpDataModelV2 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVpDataModelV2.fromParsed(input, payload);
}
