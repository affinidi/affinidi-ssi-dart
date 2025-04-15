import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../jwt/jwt_dm_v1_suite.dart';
import '../linked_data/ld_dm_v1_suite.dart';
import '../linked_data/ld_dm_v2_suite.dart';
import '../linked_data/ld_vc_data_model_v1.dart';
import '../linked_data/ld_vc_data_model_v2.dart';
import '../models/parsed_vc.dart';
import '../sdjwt/enveloped_vc_suite.dart';
import '../sdjwt/sdjwt_dm_v2_suite.dart';
import 'vc_suite.dart';

/// Place to store all supported VcSuites
class VcSuites {
  static final suites = <VerifiableCredentialSuite>[
    EnvelopedVcDm2Suite(),
    LdVcDm1Suite(),
    LdVcDm2Suite(),
    JwtDm1Suite(),
    SdJwtDm2Suite(),
  ];

  /// Return the suite that matches [vc]
  static VerifiableCredentialSuite getVcSuite(ParsedVerifiableCredential vc) {
    return switch (vc) {
      LdVcDataModelV1() => LdVcDm1Suite() as VerifiableCredentialSuite,
      LdVcDataModelV2() => LdVcDm2Suite() as VerifiableCredentialSuite,
      JwtVcDataModelV1() => JwtDm1Suite() as VerifiableCredentialSuite,
      SdJwtDataModelV2() => SdJwtDm2Suite() as VerifiableCredentialSuite,
      _ => throw SsiException(
          message: 'Suite for "${vc.runtimeType}" is not supported',
          code: SsiExceptionType.other.code,
        ),
    };
  }
}
