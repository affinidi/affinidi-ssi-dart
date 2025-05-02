import 'dart:convert';

import '../../did/did_signer.dart';
import '../../did/did_verifier.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../../util/base64_util.dart';
import '../models/parsed_vc.dart';
import '../models/v1/vc_data_model_v1.dart';
import '../parsers/jwt_parser.dart';
import '../suites/vc_suite.dart';

part 'jwt_data_model_v1.dart';

/// Options for configuring JWT issuance or parsing.
class JwtOptions {}

/// Class to parse and convert JWT token strings into a [VerifiableCredential]
final class JwtDm1Suite
    with JwtParser
    implements
        VerifiableCredentialSuite<String, VcDataModelV1, JwtVcDataModelV1> {
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
    return JwtVcDataModelV1.fromJws(jws);
  }

  /// Issues a signed [JwtVcDataModelV1] from a [VcDataModelV1] using a [DidSigner].
  ///
  /// Optionally takes [options] for JWT issuance configuration.
  Future<JwtVcDataModelV1> issue(
      {required VcDataModelV1 unsignedData, required DidSigner signer}) async {
    if (signer.did != unsignedData.issuer.id.toString()) {
      throw SsiException(
        message: 'Issuer mismatch',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    final (header, payload) =
        JwtVcDataModelV1.vcToJws(unsignedData.toJson(), signer);

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
    final jws = Jws(
        header: header,
        payload: payload,
        signature: signature,
        serialized: serialized);

    return JwtVcDataModelV1.fromJws(jws);
  }

  @override
  Future<bool> verifyIntegrity(JwtVcDataModelV1 input,
      {DateTime Function() getNow = DateTime.now}) async {
    final segments = input.serialized.split('.');

    if (segments.length != 3) {
      throw SsiException(
        message: 'Invalid JWT',
        code: SsiExceptionType.invalidVC.code,
      );
    }

    var now = getNow();
    final exp = input.jws.payload['exp'];
    if (exp != null &&
        now.isAfter(DateTime.fromMillisecondsSinceEpoch((exp as int) * 1000))) {
      return false;
    }

    final encodedHeader = segments[0];
    final encodedPayload = segments[1];
    final encodedSignature = segments[2];

    final decodedHeader = jsonDecode(
      utf8.decode(
        base64UrlNoPadDecode(encodedHeader),
      ),
    ) as Map<String, dynamic>;

    final toSign = ascii.encode('$encodedHeader.$encodedPayload');

    final did = Uri.parse(decodedHeader['kid'] as String).removeFragment();

    //TODO(FTL-20735) add discovery
    final algorithm = SignatureScheme.ecdsa_secp256k1_sha256;

    final verifier = await DidVerifier.create(
      algorithm: algorithm,
      kid: decodedHeader['kid'] as String?,
      issuerDid: did.toString(),
    );

    return verifier.verify(toSign, base64UrlNoPadDecode(encodedSignature));
  }

  @override
  String present(JwtVcDataModelV1 input) {
    return input.serialized;
  }
}
