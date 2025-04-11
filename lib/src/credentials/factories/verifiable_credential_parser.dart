import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../jwt/jwt_dm_v1_suite.dart';
import '../linked_data/ld_dm_v1_suite.dart';
import '../linked_data/ld_dm_v2_suite.dart';
import '../models/parsed_vc.dart';
import '../models/verifiable_credential.dart';
import '../sdjwt/sdjwt_dm_v2_suite.dart';
import 'vc_suite.dart';

/// Factory class supporting multiple parsers to convert data into a [VerifiableCredential]
final class VerifiableCredentialParser {
  static final _suites = <VerifiableCredentialSuite>[
    LdVcDm1Suite(),
    LdVcDm2Suite(),
    JwtDm1Suite(),
    SdJwtDm2Suite(),
  ];

  /// Returns a [VerifiableCredential] instance.
  ///
  /// A [SsiException] may be thrown with the following error code:
  /// - **unableToParseVerifiableCredential**:
  ///  - Thrown if it is unable to parse the provided data
  static ParsedVerifiableCredential parse(Object rawData) {
    for (final suite in _suites) {
      if (suite.canParse(rawData)) {
        try {
          return suite.parse(rawData);
        } catch (error, stackTrace) {
          Error.throwWithStackTrace(
              SsiException(
                  message: 'Unknown VC Data Model',
                  code: SsiExceptionType.unableToParseVerifiableCredential.code,
                  originalMessage: error.toString()),
              stackTrace);
        }
      }
    }

    Error.throwWithStackTrace(
        SsiException(
            message: 'Unknown VC Data Model',
            code: SsiExceptionType.unableToParseVerifiableCredential.code),
        StackTrace.current);
  }
}
