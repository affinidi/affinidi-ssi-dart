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
      final result = suite.tryParse(rawData);
      if (result != null) {
        return result;
      }
    }

    Error.throwWithStackTrace(
        SsiException(
            message: 'Unknown VC Data Model',
            code: SsiExceptionType.unableToParseVerifiablePresentation.code),
        StackTrace.current);
  }
}
