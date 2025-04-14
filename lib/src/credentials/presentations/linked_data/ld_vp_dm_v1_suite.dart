import '../../linked_data/ld_base_suite.dart';
import '../factories/vp_suite.dart';
import '../models/v1/vp_data_model_v1.dart';
import 'ld_vp_data_model_v1.dart';

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
          contextUrl: VpDataModelV1.contextUrl,
        );

  @override
  LdVpDataModelV1 fromParsed(String input, Map<String, dynamic> payload) =>
      LdVpDataModelV1.fromParsed(input, payload);
}
