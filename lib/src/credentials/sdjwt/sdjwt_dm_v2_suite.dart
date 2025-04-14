import 'dart:convert';
import 'dart:typed_data';

import 'package:jose_plus/jose.dart';
import 'package:sdjwt/sdjwt.dart';
import 'package:ssi/ssi.dart';
import './../../util/base64_util.dart';

import '../../did/did_signer.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/v2/vc_data_model_v2.dart';
import '../models/verifiable_credential.dart';
import '../parsers/sdjwt_parser.dart';
import '../proof/ecdsa_secp256k1_signature2019_suite.dart';
import '../suites/vc_suite.dart';
import 'sd_vc_dm_v2.dart';

class SdJwtDm2Options {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class SdJwtDm2Suite
    with
        SdJwtParser
    implements
        VerifiableCredentialSuite<String, MutableVcDataModelV2,
            SdJwtDataModelV2, SdJwtDm2Options> {
  @override
  bool hasValidPayload(SdJwt data) {
    final context = data.payload[VcDataModelV2Key.context.key];
    return (context is List) &&
        context.contains(MutableVcDataModelV2.contextUrl);
  }

  @override
  bool canParse(Object input) {
    if (input is! String) return false;
    return canDecode(input);
  }

  @override
  SdJwtDataModelV2 parse(Object input) {
    if (input is! String) {
      throw SsiException(
        message: 'Only String is supported',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }

    return SdJwtDataModelV2.fromSdJwt(decode(input));
  }

  @override
  Future<SdJwtDataModelV2> issue(
    MutableVcDataModelV2 vc,
    DidSigner signer, {
    SdJwtDm2Options? options,
  }) async {
    //TODO(cm): extend option to select proof suite

    throw UnimplementedError();
  }

  @override
  Future<bool> verifyIntegrity(SdJwtDataModelV2 input) async {
    //TODO(cm): return verification result
    //TODO(cm): discover proof type
    final sdjwt = input.sdJwt;

    final parts = sdjwt.serialized.split('~').first.split('.');

    final payloadJson = jsonDecode(
      utf8.decode(base64Url.decode(addBase64Padding(parts[1]))),
    );

    final headerJson = jsonDecode(
      utf8.decode(base64Url.decode(addBase64Padding(parts[0]))),
    );
    final alg = SdJwtSignAlgorithm.fromString(headerJson['alg']);

    if (payloadJson['cnf'] == null) {
      throw SsiException(
          message: 'sdJwt should have a valid `cnf` claim',
          code: SsiExceptionType.other.code);
    }

    final jwk = jsonEncode(payloadJson['cnf']['jwk']);
    final publicKey = SdPublicKey(jwk, alg);
    final verifier = SDKeyVerifier(publicKey);
    final sdJwyVerifier = SdJwtHandlerV1();
    final result = sdJwyVerifier.verify(sdJwt: input.sdJwt, verifier: verifier);

    return result.isVerified!;
  }

  String addBase64Padding(String str) {
    if (str.isEmpty) return str;
    final padLength = 4 - (str.length % 4);
    return padLength == 4 ? str : str + ('=' * padLength);
  }
}
