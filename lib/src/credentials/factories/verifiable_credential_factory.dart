import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../models/verifiable_credential.dart';
import '../parsers/jwt_vc_data_model_v11_parser.dart';
import '../parsers/sdjwt_data_model_v20_parser.dart';
import '../parsers/vc_data_model_parser.dart';
import '../parsers/vc_data_model_v11_with_proof_parser.dart';
import '../parsers/vc_data_model_v20_with_proof_parser.dart';

/// Factory class supporting multiple parsers to convert data into a [VerifiableCredential]
final class VerifiableCredentialFactory {
  static final _credentialDataModelParsers = <VcDataModelParser>[
    VcDataModelV11WithProofParser(),
    VcDataModelV20WithProofParser(),
    JwtVcDataModelV11Parser(),
    SdJwtDataModelV20Parser(),
  ];

  /// Returns a [VerifiableCredential] instance.
  ///
  /// A [SsiException] may be thrown with the following error code:
  /// - **unableToParseVerifiableCredential**:
  ///  - Thrown if it is unable to parse the provided data
  static VerifiableCredential create(Object rawData) {
    for (final parser in _credentialDataModelParsers) {
      if (parser.canParse(rawData)) {
        try {
          return parser.parse(rawData);
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
