import 'dart:developer' as developer;

import 'package:sdjwt/sdjwt.dart';
import 'package:ssi/src/credentials/factories/vc_suite.dart';
import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'package:ssi/src/credentials/sdjwt/sd_vc_dm_v2.dart';
import 'package:ssi/src/did/did_signer.dart';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/verifiable_credential.dart';
import '../proof/ecdsa_secp256k1_signature2019_suite.dart';

class SdJwtDm2Options {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class SdJwtDm2Suite
    implements
        VerifiableCredentialSuite<String, VcDataModelV2, SdJwtDataModelV2,
            SdJwtDm2Options> {
  bool _hasV2Context(Object data) {
    if (data is! Map) return false;

    final context = data[VcDataModelV2Key.context.key];
    return (context is List) && context.contains(VcDataModelV2.contextUrl);
  }

  @override
  bool canParse(Object input) {
    if (input is! String) return false;

    // filter out other strings
    if (!input.startsWith('ey')) return false;

    // FIXME(cm) decoding twice in canParse and parse
    try {
      SdJwt jwt = SdJwt.parse(input);
      if (!_hasV2Context(jwt)) return false;
    } catch (e) {
      developer.log(
        "SdJwtDm2Suite decode failed",
        level: 500, // FINE
        error: e,
      );
      return false;
    }

    return true;
  }

  @override
  SdJwtDataModelV2 parse(Object input) {
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

    SdJwt jwt = SdJwt.parse(input);
    return SdJwtDataModelV2.fromSdJwt(jwt);
  }

  @override
  Future<SdJwtDataModelV2> issue(
    VcDataModelV2 vc,
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
    final proofSuite = EcdsaSecp256k1Signature2019();
    final verificationResult = await proofSuite.verifyProof(
      input.sdJwt.payload,
    );

    return verificationResult.isValid;
  }
}
