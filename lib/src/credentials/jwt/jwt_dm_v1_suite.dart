import '../../did/did_signer.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../factories/vc_suite.dart';
import '../models/v1/vc_data_model_v1.dart';
import '../models/verifiable_credential.dart';
import 'jwt_data_model_v1.dart';

class JwtOptions {}

/// Class to parse and convert JWT token strings into a [VerifiableCredential]
final class JwtDm1Suite
    implements VerifiableCredentialSuite<String, JwtOptions> {
  /// Checks if the [data] provided matches the right criteria to attempt a parse
  /// [data] must be a valid jwt string with a header a payload and a signature
  @override
  bool canParse(Object data) {
    if (data is! String) return false;

    return data.startsWith('ey') && data.split('.').length == 3;
  }

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  @override
  JwtVcDataModelV1 parse(Object data) {
    return JwtVcDataModelV1.parse(data as String);
  }

  @override
  Future<String> issue(
    VerifiableCredential vc,
    DidSigner signer, {
    JwtOptions? options,
  }) {
    if (vc is! VcDataModelV1) {
      throw SsiException(
        message: 'Only VCDM v1 is supported',
        code: SsiExceptionType.other.code,
      );
    }

    return JwtVcDataModelV1.encode(vc, signer);
  }

  @override
  Future<bool> verifyIntegrity(String input) {
    final jwtVc = parse(input);

    return jwtVc.hasIntegrity;
  }
}
