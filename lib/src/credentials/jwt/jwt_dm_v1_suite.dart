import 'dart:convert';

import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';
import 'package:ssi/src/credentials/parsers/jwt_parser.dart';
import 'package:ssi/src/did/did_signer.dart';
import 'package:ssi/src/did/did_verifier.dart';
import 'package:ssi/src/types.dart';
import 'package:ssi/src/util/base64_util.dart';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../factories/vc_suite.dart';
import '../models/verifiable_credential.dart';
import 'jwt_data_model_v1.dart';

class JwtOptions {}

/// Class to parse and convert JWT token strings into a [VerifiableCredential]
final class JwtDm1Suite extends VerifiableCredentialSuite<String, VcDataModelV1,
    JwtVcDataModelV1, JwtOptions> with JwtParser {
  /// Checks if the [data] provided matches the right criteria to attempt a parse
  /// [data] must be a valid jwt string with a header a payload and a signature
  @override
  bool canParse(Object data) {
    if (data is! String) return false;

    return canDecode(data);
  }

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  @override
  JwtVcDataModelV1 parse(Object data) {
    if (data is! String) {
      throw SsiException(
        message: 'Only String is supported',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }

    final jws = decode(data);
    final vcPayload = JwtVcDataModelV1.jwtToJson(jws.payload);
    return JwtVcDataModelV1.fromJson({...vcPayload, 'jws': jws});
  }

  @override
  Future<JwtVcDataModelV1> issue(
    VcDataModelV1 vc,
    DidSigner signer, {
    JwtOptions? options,
  }) async {
    final (header, payload) = JwtVcDataModelV1.vcToJwt(vc.toJson(), signer);

    final encodedHeader = base64UrlNoPadEncode(
      utf8.encode(jsonEncode(header)),
    );
    final encodedPayload = base64UrlNoPadEncode(
      utf8.encode(jsonEncode(payload)),
    );

    final toSign = ascii.encode('$encodedHeader.$encodedPayload');

    final signature = base64UrlNoPadEncode(
      await signer.sign(toSign),
    );

    final serialized = '$encodedHeader.$encodedPayload.$signature';
    final jws = JWS(
        header: header,
        payload: payload,
        signature: signature,
        serialized: serialized);

    final vcPayload = JwtVcDataModelV1.jwtToJson(jws.payload);
    return JwtVcDataModelV1.fromJson({...vcPayload, 'jws': jws});
  }

  @override
  Future<bool> verifyIntegrity(JwtVcDataModelV1 input) async {
    final segments = input.serialized.split('.');

    if (segments.length != 3) {
      throw SsiException(
        message: 'Invalid JWT',
        code: SsiExceptionType.invalidVC.code,
      );
    }

    final encodedHeader = segments[0];
    final encodedPayload = segments[1];
    final encodedSignature = segments[2];

    final decodedHeader = jsonDecode(
      utf8.decode(
        base64UrlNoPadDecode(encodedHeader),
      ),
    );

    final toSign = ascii.encode('$encodedHeader.$encodedPayload');

    Uri did = Uri.parse(decodedHeader['kid']).removeFragment();

    //TODO(cm) add discovery
    final algorithm = SignatureScheme.ecdsa_secp256k1_sha256;

    final verifier = await DidVerifier.create(
      algorithm: algorithm,
      kid: decodedHeader['kid'],
      issuerDid: did.toString(),
    );

    return verifier.verify(toSign, base64UrlNoPadDecode(encodedSignature));
  }
}
