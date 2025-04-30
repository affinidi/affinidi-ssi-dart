import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/parsed_vc.dart';
import '../models/verifiable_credential.dart';
import 'vc_suites.dart';

/// Entry point to all supported Verifiable Credential (VC) parsers.
///
/// Attempts to automatically detect and parse the input [rawData]
/// using the available VC suites registered in [VcSuites].
final class UniversalParser {
  /// Returns a [VerifiableCredential] instance.
  ///
  /// A [SsiException] may be thrown with the following error code:
  /// - **unableToParseVerifiableCredential**:
  ///  - Thrown if it is unable to parse the provided data
  static ParsedVerifiableCredential parse(Object rawData) {
    for (final suite in VcSuites.suites) {
      // FIXME(FTL-20737) decoding twice in canParse and parse
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
