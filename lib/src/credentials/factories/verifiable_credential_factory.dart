import 'package:ssi/src/credentials/parsers/vc_data_model_v1_with_proof_parser.dart';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/verifiable_credential.dart';
import '../parsers/jwt_vc_data_model_v1_parser.dart';
import '../parsers/sdjwt_data_model_v2_parser.dart';
import '../parsers/vc_data_model_parser.dart';
import '../parsers/vc_data_model_v2_with_proof_parser.dart';

/// Factory class supporting multiple parsers to convert data into a [VerifiableCredential]
final class VerifiableCredentialFactory {
  //parser to type map where Type tells what dat type is expected by parser
  //the problem is, dart uses type erasures and during runtime the type info
  //is not stored for generics.
  static final _credentialDataModelParsersMap = <VcDataModelParser, Type>{
    VcDataModelV1WithProofParser() : <String, dynamic>{}.runtimeType,
    VcDataModelV2WithProofParser() : <String, dynamic>{}.runtimeType,
    JwtVcDataModelV1Parser() : "".runtimeType,
    SdJwtDataModelV2Parser() : "".runtimeType
  };

  /// Returns a [VerifiableCredential] instance.
  ///
  /// A [SsiException] may be thrown with the following error code:
  /// - **unableToParseVerifiableCredential**:
  ///  - Thrown if it is unable to parse the provided data
  static VerifiableCredential create(Object rawData) {
    for (final parserEntry in _credentialDataModelParsersMap.entries) {
      if (parserEntry.value == rawData.runtimeType && parserEntry.key.canParse(rawData)) {
        try {
          return parserEntry.key.parse(rawData);
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
