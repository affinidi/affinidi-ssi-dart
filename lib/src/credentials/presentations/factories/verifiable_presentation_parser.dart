import 'package:ssi/src/credentials/factories/vc_suite.dart';
import 'package:ssi/src/credentials/presentations/linked_data/ld_dm_v1_suite.dart';
import 'package:ssi/src/credentials/presentations/models/parsed_vp.dart';
import 'package:ssi/src/credentials/presentations/models/verifiable_presentation.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';

import '../linked_data/ld_dm_v2_suite.dart';

/// Factory class supporting multiple parsers to convert data into a [VerifiableCredential]
final class VerifiableCredentialParser {
  static final _suites = <VerifiableCredentialSuite<dynamic,
      VerifiablePresentation, ParsedVerifiablePresentation, dynamic>>[
    LdVpDm1Suite(),
    LdVpDm2Suite(),
  ];

  /// Returns a [VerifiableCredential] instance.
  ///
  /// A [SsiException] may be thrown with the following error code:
  /// - **unableToParseVerifiableCredential**:
  ///  - Thrown if it is unable to parse the provided data
  static ParsedVerifiablePresentation parse(Object rawData) {
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
