import '../../../exceptions/ssi_exception.dart';
import '../../../exceptions/ssi_exception_type.dart';
import '../models/parsed_vp.dart';
import 'vp_suites.dart';

/// Entry point to all supported VC parsers
final class UniversalPresentationParser {
  /// Returns a [ParsedVerifiablePresentation] instance.
  ///
  /// A [SsiException] may be thrown with the following error code:
  /// - **unableToParseVerifiableCredential**:
  ///  - Thrown if it is unable to parse the provided data
  static ParsedVerifiablePresentation parse(Object rawData) {
    for (final suite in VpSuites.suites) {
      // FIXME(FTL-20737) decoding twice in canParse and parse
      if (suite.canParse(rawData)) {
        try {
          return suite.parse(rawData);
        } catch (error, stackTrace) {
          Error.throwWithStackTrace(
              SsiException(
                  message: 'Unknown VP Data Model',
                  code:
                      SsiExceptionType.unableToParseVerifiablePresentation.code,
                  originalMessage: error.toString()),
              stackTrace);
        }
      }
    }

    Error.throwWithStackTrace(
        SsiException(
            message: 'Unknown VC Data Model',
            code: SsiExceptionType.unableToParseVerifiablePresentation.code),
        StackTrace.current);
  }
}
