import 'package:sdjwt/sdjwt.dart';

import '../../did/did_signer.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/v2/vc_data_model_v2.dart';
import '../parsers/sdjwt_parser.dart';
import '../proof/ecdsa_secp256k1_signature2019_suite.dart';
import '../suites/vc_suite.dart';
import 'sd_vc_dm_v2.dart';

/// Options for SD-JWT Data Model v2 operations.
class SdJwtDm2Options {}

/// Suite for working with W3C VC Data Model v2 credentials in SD-JWT format.
///
/// Provides methods to parse, validate, and issue Verifiable Credentials
/// represented as Selective Disclosure JWT (SD-JWT) according to the
/// W3C Data Model v2 specification.
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
    //TODO(FTL-20735): extend option to select proof suite

    throw UnimplementedError();
  }

  @override
  Future<bool> verifyIntegrity(SdJwtDataModelV2 input) async {
    //TODO(FTL-20735): discover proof type
    final proofSuite = EcdsaSecp256k1Signature2019();
    final verificationResult = await proofSuite.verifyProof(
      input.sdJwt.payload,
      EcdsaSecp256k1Signature2019VerifyOptions(),
    );

    return verificationResult.isValid;
  }
}
