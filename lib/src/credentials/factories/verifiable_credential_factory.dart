import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/verifiable_credential.dart';
import '../parsers/jwt_vc_data_model_v1_parser.dart';
import '../parsers/sdjwt_data_model_v2_parser.dart';
import '../parsers/vc_data_model_parser.dart';
import '../parsers/vc_data_model_v1_with_proof_parser.dart';
import '../parsers/vc_data_model_v2_with_proof_parser.dart';

/// Factory class supporting multiple parsers to convert data into a [VerifiableCredential]
final class VerifiableCredentialFactory {
  static final _credentialDataModelParsers = <VcDataModelParser>[
    VcDataModelV1WithProofParser(),
    VcDataModelV2WithProofParser(),
    JwtVcDataModelV1Parser(),
    SdJwtDataModelV2Parser(),
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
