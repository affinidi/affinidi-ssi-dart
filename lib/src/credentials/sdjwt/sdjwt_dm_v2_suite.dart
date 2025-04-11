import 'dart:convert';
import 'dart:developer' as developer;

import 'package:sdjwt/sdjwt.dart';

import '../../did/did_signer.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/parsed_vc.dart';
import '../models/v1/vc_data_model_v1.dart';
import '../models/verifiable_credential.dart';
import '../proof/ecdsa_secp256k1_signature2019_suite.dart';
import '../suites/vc_suite.dart';
import 'sd_vc_dm_v2.dart';

class SdJwtDm2Options {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class SdJwtDm2Suite
    implements VerifiableCredentialSuite<String, SdJwtDm2Options> {
  static const _v2ContextUrl = 'https://www.w3.org/ns/credentials/v2';

  bool _hasV2Context(Object data) {
    if (data is! Map) return false;

    final context = data[VcDataModelV1Key.context.key];
    return (context is List) && context.contains(_v2ContextUrl);
  }

  @override
  bool canParse(Object input) {
    if (input is! String) return false;

    // filter out other strings
    if (!input.startsWith('ey')) return false;

    // FIXME(cm) decoding twice in canParse and parse
    try {
      var jwt = SdJwt.parse(input);
      if (!_hasV2Context(jwt)) return false;
    } catch (e) {
      developer.log(
        'LdVcDm1Suite decode failed',
        level: 500, // FINE
        error: e,
      );
      return false;
    }

    return true;
  }

  @override
  ParsedVerifiableCredential<String> parse(Object input) {
    if (input is! String) {
      throw SsiException(
        message: 'Only String is supported',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }

    // filter out other strings
    if (!input.startsWith('ey')) {
      throw SsiException(
        message: 'Not a SDJWT',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }

    var jwt = SdJwt.parse(input);
    return SdJwtDataModelV2.fromSdJwt(jwt);
  }

  @override
  Future<String> issue(
    VerifiableCredential vc,
    DidSigner signer, {
    SdJwtDm2Options? options,
  }) async {
    //TODO(cm): extend option to select proof suite

    return '';
  }

  @override
  Future<bool> verifyIntegrity(String input) async {
    //TODO(cm): return verification result
    //TODO(cm): discover proof type
    final proofSuite = EcdsaSecp256k1Signature2019();
    final verificationResult = await proofSuite.verifyProof(
      jsonDecode(input) as Map<String, dynamic>,
    );

    return verificationResult.isValid;
  }
}
