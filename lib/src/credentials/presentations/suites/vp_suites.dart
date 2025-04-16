import '../../../exceptions/ssi_exception.dart';
import '../../../exceptions/ssi_exception_type.dart';
import '../linked_data/ld_vp_dm_v1_suite.dart';
import '../linked_data/ld_vp_dm_v2_suite.dart';
import '../models/parsed_vp.dart';
import 'vp_suite.dart';

/// Place to store all supported VcSuites
class VpSuites {
  static final suites = <VerifiablePresentationSuite>[
    LdVpDm1Suite(),
    LdVpDm2Suite()
  ];

  /// Return the suite that matches [vp]
  static VerifiablePresentationSuite getVpSuite(
      ParsedVerifiablePresentation vp) {
    return switch (vp) {
      LdVpDataModelV1() => LdVpDm1Suite() as VerifiablePresentationSuite,
      LdVpDataModelV2() => LdVpDm2Suite() as VerifiablePresentationSuite,
      _ => throw SsiException(
          message: 'Suite for "${vp.runtimeType}" is not supported',
          code: SsiExceptionType.other.code,
        ),
    };
  }
}
