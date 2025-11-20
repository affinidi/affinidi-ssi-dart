import 'package:selective_disclosure_jwt/selective_disclosure_jwt.dart';

import '../../did/did_resolver.dart';
import '../../did/did_signer.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../models/sdjwt_signer_adapter.dart';
import '../models/parsed_vc.dart';
import '../models/v2/vc_data_model_v2.dart';
import '../parsers/sdjwt_parser.dart';
import '../suites/vc_suite.dart';
import 'enveloped_vc_suite.dart';
import 'sdjwt_did_verifier.dart';

/// Suite for working with W3C VC Data Model v2 credentials in SD-JWT format.
///
/// Provides methods to parse, validate, and issue Verifiable Credentials
/// represented as Selective Disclosure JWT (SD-JWT) according to the
/// W3C Data Model v2 specification.
final class SdJwtDm2Suite
    with SdJwtParser
    implements
        VerifiableCredentialSuite<String, VcDataModelV2, SdJwtDataModelV2> {
  /// Checks if the SD-JWT payload represents a valid VC Data Model v2 structure.
  ///
  /// [data] - The SD-JWT structure to validate.
  ///
  /// Returns true if the payload contains a context array with the required
  /// VC Data Model v2 context URL.
  @override
  bool hasValidPayload(SdJwt data) {
    final context = data.payload[VcDataModelV2Key.context.key];
    return (context is List) && context.contains(dmV2ContextUrl);
  }

  /// Determines if the provided input can be parsed by this suite.
  ///
  /// [input] - The data to check for parseability.
  ///
  /// Returns true if the input is a String and can be decoded as an SD-JWT.
  @override
  bool canParse(Object input) {
    if (input is! String) return false;
    return canDecode(input);
  }

  /// Parses the input string into an SD-JWT data model.
  ///
  /// [input] - The string to parse as an SD-JWT credential.
  ///
  /// Returns a parsed SD-JWT credential model.
  ///
  /// Throws [SsiException] if the input is not a String.
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

  /// Attempts to parse the [input] and returns the result if successful, null otherwise.
  ///
  /// This method combines validation and parsing in one step to avoid redundant operations.
  @override
  SdJwtDataModelV2? tryParse(Object input) {
    if (!canParse(input)) return null;

    try {
      return parse(input);
    } catch (e) {
      return null;
    }
  }

  @override
  Map<String, dynamic> present(SdJwtDataModelV2 input) =>
      EnvelopedVcDm2Suite().present(input);

  /// Issues a new SD-JWT credential by signing the VC with the provided signer.
  ///
  /// [unsignedData] - The credential to be issued.
  /// [signer] - The DID signer used to sign the credential.
  /// [disclosureFrame] - (optional) Defines which fields in the VC should be selectively disclosable.
  /// A map structure that specifies which parts of the credential should be
  /// made available for selective disclosure.
  /// [hasher] - (optional) Hasher implementation for generating disclosure digests.
  /// Defaults to SHA-256 algorithm for hashing if not specified.
  /// [holderPublicKey] - (optional) The holder's public key for binding the credential to the holder.
  /// Used for key binding to ensure the credential can only be presented
  /// by the intended holder.
  ///
  /// Returns a parsed SD-JWT credential with appropriate signatures and disclosures.
  ///
  /// Throws [SsiException] if the credential is invalid or if signing fails.
  Future<SdJwtDataModelV2> issue(
      {required VcDataModelV2 unsignedData,
      required DidSigner signer,
      Map<String, dynamic>? disclosureFrame,
      Hasher<String, String>? hasher,
      SdPublicKey? holderPublicKey}) async {
    final payload = unsignedData.toJson();

    if (signer.did != unsignedData.issuer.id.toString()) {
      throw SsiException(
        message: 'Issuer mismatch',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    final jwtClaims = <String, dynamic>{};
    final exp = payload[_VC2.validUntil.key];
    if (exp != null) {
      payload['exp'] =
          (DateTime.parse(exp as String).millisecondsSinceEpoch / 1000).floor();
    }

    final nbf = payload[_VC2.validFrom.key];
    if (nbf != null) {
      payload['nbf'] =
          (DateTime.parse(nbf as String).millisecondsSinceEpoch / 1000).floor();
    }
    jwtClaims.addAll(payload);

    final validUntil = payload.remove(VcDataModelV2Key.validUntil.key);
    if (validUntil != null) {
      jwtClaims['exp'] =
          (DateTime.parse(validUntil as String).millisecondsSinceEpoch / 1000)
              .floor();
    }

    final validFrom = payload.remove(VcDataModelV2Key.validFrom.key);
    if (validFrom != null) {
      jwtClaims['nbf'] =
          (DateTime.parse(validFrom as String).millisecondsSinceEpoch / 1000)
              .floor();
    }

    jwtClaims['iat'] = (DateTime.now().millisecondsSinceEpoch / 1000).floor();

    disclosureFrame ??= _getDefaultDisclosureFrame(payload);

    final jwtSigner = _createSdJwtSigner(signer);
    final handler = SdJwtHandlerV1();

    try {
      final sdJwt = handler.sign(
        claims: jwtClaims,
        disclosureFrame: disclosureFrame,
        signer: jwtSigner,
        hasher: hasher ?? Base64EncodedOutputHasher.base64Sha256,
        holderPublicKey: holderPublicKey,
      );
      return SdJwtDataModelV2.fromSdJwt(await sdJwt);
    } catch (e, stacktrace) {
      Error.throwWithStackTrace(
          SsiException(
            message: 'Failed to issue SD-JWT credential: ${e.toString()}',
            code: SsiExceptionType.invalidVC.code,
            originalMessage: e.toString(),
          ),
          stacktrace);
    }
  }

  /// Verifies the cryptographic integrity of the credential.
  ///
  /// [input] - The SD-JWT credential to verify.
  /// [didResolver] - Optional custom DID resolver for offline/test verification.
  ///
  /// Returns true if the credential's signature is valid, false otherwise.
  @override
  Future<bool> verifyIntegrity(SdJwtDataModelV2 input,
      {DateTime Function() getNow = DateTime.now,
      DidResolver? didResolver}) async {
    final algorithm =
        SignatureScheme.fromAlg(input.sdJwt.header['alg'] as String);
    var now = getNow();
    final exp = input.sdJwt.payload['exp'];
    if (exp != null &&
        now.isAfter(DateTime.fromMillisecondsSinceEpoch((exp as int) * 1000))) {
      return false;
    }

    final nbf = input.sdJwt.payload['nbf'];
    if (nbf != null &&
        now.isBefore(
            DateTime.fromMillisecondsSinceEpoch((nbf as int) * 1000))) {
      return false;
    }

    final verifier = await SdJwtDidVerifier.create(
      algorithm: algorithm,
      kid: input.sdJwt.header['kid'] as String?,
      issuerDid: input.issuer.id.toString(),
      didResolver: didResolver,
    );

    final SdJwt(:bool? isVerified) = SdJwtHandlerV1().verify(
      sdJwt: input.sdJwt,
      verifier: verifier,
    );

    return isVerified!;
  }

  /// Creates a default disclosure frame if none is provided.
  ///
  /// [payload] - The credential payload.
  ///
  /// Returns a disclosure frame that makes all credential subject fields
  /// selectively disclosable.
  Map<String, dynamic> _getDefaultDisclosureFrame(
      Map<String, dynamic> payload) {
    final credentialSubject = payload['credentialSubject'] as dynamic;
    if (credentialSubject != null &&
        credentialSubject is Map &&
        credentialSubject.isNotEmpty) {
      return {
        'credentialSubject': {
          '_sd': credentialSubject.keys.toList(),
        }
      };
    } else {
      return {};
    }
  }
}

/// Creates an SD-JWT signer from a DID signer.
///
/// [signer] - The DID signer to wrap.
///
/// Returns a Signer implementation for SD-JWT operations.
Signer _createSdJwtSigner(DidSigner signer) {
  return SdJwtSignerAdapter(signer);
}

/// A [VcDataModelV2] backed by an SD-JWT credential structure.
///
/// Represents a Verifiable Credential in the W3C Data Model v2 format
/// issued and managed as a Selective Disclosure JWT (SD-JWT).
class SdJwtDataModelV2 extends VcDataModelV2
    implements ParsedVerifiableCredential<String> {
  /// The underlying [SdJwt] object representing the signed credential.
  final SdJwt sdJwt;

  /// Creates an [SdJwtDataModelV2] from a parsed [SdJwt] object.
  SdJwtDataModelV2.fromSdJwt(this.sdJwt)
      : super.clone(VcDataModelV2.fromJson(sdJwt.claims));

  @override
  String get serialized => sdJwt.serialized;

  /// Returns the header section of the SD-JWT.
  Map<String, dynamic> get header => sdJwt.header;

  /// Returns the set of selective disclosure claims (disclosures).
  Set<Disclosure> get disclosures => Set.unmodifiable(sdJwt.disclosures);
}

typedef _VC2 = VcDataModelV2Key;
