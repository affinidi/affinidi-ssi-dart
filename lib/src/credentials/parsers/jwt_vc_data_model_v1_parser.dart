import '../models/v1/jwt_data_model_v1.dart';
import '../models/verifiable_credential.dart';
import 'vc_data_model_parser.dart';

/// Class to parse and convert JWT token strings into a [VerifiableCredential]
final class JwtVcDataModelV1Parser extends VcDataModelParser<String, JwtVcDataModelV1> {
  /// Checks if the [data] provided matches the right criteria to attempt a parse
  /// [data] must be a valid jwt string with a header a payload and a signature
  @override
  bool canParse(String data) {
    return data.split('.').length == 3;
  }

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  @override
  JwtVcDataModelV1 parse(String data) {
    return JwtVcDataModelV1(data);
  }
}
