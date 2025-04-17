import 'dart:convert';

import '../../../ssi.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../util/base64_util.dart';
import '../models/parsed_vc.dart';
import '../models/v1/vc_data_model_v1.dart';
import '../models/v1/vc_data_model_v1_view.dart';
import '../parsers/jwt_parser.dart';
import '../suites/vc_suite.dart';

part 'jwt_data_model_v1.dart';

class JwtOptions {}

/// Class to parse and convert JWT token strings into a [VerifiableCredential]
final class JwtDm1Suite
    with
        JwtParser
    implements
        VerifiableCredentialSuite<String, VcDataModelV1, JwtVcDataModelV1,
            JwtOptions> {
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
    return _JwtVcDataModelV1.fromJws(jws);
  }

  @override
  Future<JwtVcDataModelV1> issue(
    VcDataModelV1 vc,
    DidSigner signer, {
    JwtOptions? options,
  }) async {
    // Validate the credential before issuing
    _validateCredential(vc);

    final (header, payload) = JwtVcDataModelV1.vcToJws(vc.toJson(), signer);

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

    return _JwtVcDataModelV1.fromJws(jws);
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
    ) as Map<String, dynamic>;

    final toSign = ascii.encode('$encodedHeader.$encodedPayload');

    final did = Uri.parse(decodedHeader['kid'] as String).removeFragment();

    //TODO(FTL-20735) add discovery
    final algorithm = SignatureScheme.ecdsa_secp256k1_sha256;

    final verifier = await DidVerifier.create(
      algorithm: algorithm,
      kid: decodedHeader['kid'] as String,
      issuerDid: did.toString(),
    );

    return verifier.verify(toSign, base64UrlNoPadDecode(encodedSignature));
  }

  @override
  String present(JwtVcDataModelV1 input) {
    return input.serialized;
  }

  /// Validates the credential before issuing.
  ///
  /// [vc] - The credential to validate.
  ///
  /// Throws [SsiException] if any required fields are missing or invalid.
  void _validateCredential(VcDataModelV1 vc) {
    final List<String> errors = [];

    //todo: crosscheck with team on vc_data_model_v1.dart line 124-135,
    // it seems most of teh checks are already there
    // the only additional here is presence of contextUrl.

    // Check required fields according to W3C VC Data Model v1.0 spec
    if (vc.context.isEmpty) {
      errors.add('Context is required');
    } else if (!vc.context.contains(MutableVcDataModelV1.contextUrl)) {
      errors.add('Context must include ${MutableVcDataModelV1.contextUrl}');
    }

    if (vc.type.isEmpty) {
      errors.add('Type is required');
    } else if (!vc.type.contains('VerifiableCredential')) {
      errors.add('Type must include "VerifiableCredential"');
    }

    if (vc.issuer.isEmpty) {
      errors.add('Issuer is required');
    }

    if (vc.credentialSubject.isEmpty) {
      errors.add('Credential subject is required and cannot be empty');
    }

    // If any errors were found, throw an exception
    if (errors.isNotEmpty) {
      throw SsiException(
        message: 'Invalid VC: ${errors.join(', ')}',
        code: SsiExceptionType.invalidVC.code,
      );
    }
  }
}
