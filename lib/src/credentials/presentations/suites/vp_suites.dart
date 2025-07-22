import '../../../exceptions/ssi_exception.dart';
import '../../../exceptions/ssi_exception_type.dart';
import '../../proof/embedded_proof_suite.dart';
import '../linked_data/ld_vp_dm_v1_suite.dart';
import '../linked_data/ld_vp_dm_v2_suite.dart';
import '../models/parsed_vp.dart';
import 'vp_suite.dart';

/// /// Registry of all supported Verifiable Presentation suites.
///
/// Provides a way to resolve the appropriate [VerifiablePresentationSuite]
/// implementation based on the parsed presentation instance.
///
/// Currently supports:
/// - [LdVpDm1Suite] for W3C VC Data Model v1
/// - [LdVpDm2Suite] for W3C VC Data Model v2
class VpSuites {
  /// The list of all registered [VerifiablePresentationSuite] implementations.
  static final suites = <VerifiablePresentationSuite>[
    LdVpDm1Suite(),
    LdVpDm2Suite()
  ];

  /// Return the suite that matches [vp]
  /// 
  /// [vp] - The parsed verifiable presentation to find a suite for.
  ///
  /// Returns the matching VerifiablePresentationSuite for the presentation type.
  ///
  /// Throws [SsiException] if no suite is available for the presentation type.
  static VerifiablePresentationSuite getVpSuite(
      ParsedVerifiablePresentation vp) {
    return VpSuites.getVpSuiteWithDocumentLoader(vp, null);
  }

  /// Return the suite that matches [vp] with a custom document loader.
  ///
  /// [vp] - The parsed verifiable presentation to find a suite for.
  /// [customDocumentLoader] - Optional custom document loader for loading external resources.
  ///
  /// Returns the matching VerifiablePresentationSuite for the presentation type.
  ///
  /// Throws [SsiException] if no suite is available for the presentation type.
  static VerifiablePresentationSuite getVpSuiteWithDocumentLoader(
      ParsedVerifiablePresentation vp, DocumentLoader? customDocumentLoader) {
    return switch (vp) {
      LdVpDataModelV1() =>
        LdVpDm1Suite(customDocumentLoader: customDocumentLoader)
            as VerifiablePresentationSuite,
      LdVpDataModelV2() =>
        LdVpDm2Suite(customDocumentLoader: customDocumentLoader)
            as VerifiablePresentationSuite,
      _ => throw SsiException(
          message: 'Suite for "${vp.runtimeType}" is not supported',
          code: SsiExceptionType.other.code,
        ),
    };
  }
}
