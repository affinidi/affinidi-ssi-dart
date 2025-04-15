import 'package:sdjwt/sdjwt.dart';

import '../../../ssi.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/parsed_vc.dart';
import '../models/v2/vc_data_model_v2.dart';
import '../models/v2/vc_data_model_v2_view.dart';
import '../parsers/sdjwt_parser.dart';
import '../suites/vc_suite.dart';
import 'sdjwt_did_verfier.dart';

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

    return _SdJwtDataModelV2.fromSdJwt(decode(input));
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
    final algorithm =
        SignatureScheme.fromString(input.sdJwt.header['alg'] as String);

    final verifier = await SdJwtDidVerifier.create(
      algorithm: algorithm,
      kid: (input.sdJwt.header['kid'] as String?) ?? '',
      issuerDid: input.issuer,
    );

    final SdJwt(:bool? isVerified) = SdJwtHandlerV1().verify(
      sdJwt: input.sdJwt,
      verifier: verifier,
    );

    return isVerified!;
  }
}

abstract interface class SdJwtDataModelV2
    implements ParsedVerifiableCredential<String>, VcDataModelV2 {
  SdJwt get sdJwt;
}

class _SdJwtDataModelV2 extends MutableVcDataModelV2
    implements SdJwtDataModelV2 {
  @override
  final SdJwt sdJwt;
  _SdJwtDataModelV2.fromSdJwt(this.sdJwt) : super.fromJson(sdJwt.claims);

  @override
  String get serialized => sdJwt.serialized;

  Map<String, dynamic> get header => sdJwt.header;

  Set<Disclosure> get disclosures => Set.unmodifiable(sdJwt.disclosures);
}
