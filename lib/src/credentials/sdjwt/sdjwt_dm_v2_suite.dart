import 'dart:typed_data';

import 'package:selective_disclosure_jwt/selective_disclosure_jwt.dart';

import '../../did/did_signer.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../models/parsed_vc.dart';
import '../models/v2/vc_data_model_v2.dart';
import '../models/v2/vc_data_model_v2_view.dart';
import '../parsers/sdjwt_parser.dart';
import '../suites/vc_suite.dart';
import 'enveloped_vc_suite.dart';
import 'sdjwt_did_verifier.dart';

/// Options for SD-JWT Data Model v2 operations.
///
/// Contains configuration parameters for selective disclosure JWT operations
/// in the context of W3C Verifiable Credentials Data Model v2.
class SdJwtDm2Options {
  /// Defines which fields in the VC should be selectively disclosable.
  ///
  /// A map structure that specifies which parts of the credential should be
  /// made available for selective disclosure.
  final Map<String, dynamic>? disclosureFrame;

  /// Hasher implementation for generating disclosure digests.
  ///
  /// Defaults to SHA-256 algorithm for hashing if not specified.
  final Hasher<String, String>? hasher;

  /// The holder's public key for binding the credential to the holder.
  ///
  /// Used for key binding to ensure the credential can only be presented
  /// by the intended holder.
  final SdPublicKey? holderPublicKey;

  /// Creates an options object for SD-JWT Data Model v2 operations.
  ///
  /// [disclosureFrame] - Specifies which fields should be selectively disclosable.
  /// [hasher] - The hashing algorithm implementation to use for disclosures.
  /// [holderPublicKey] - Public key of the credential holder for key binding.
  SdJwtDm2Options({
    this.disclosureFrame,
    this.hasher,
    this.holderPublicKey,
  });
}

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
  /// Checks if the SD-JWT payload represents a valid VC Data Model v2 structure.
  ///
  /// [data] - The SD-JWT structure to validate.
  ///
  /// Returns true if the payload contains a context array with the required
  /// VC Data Model v2 context URL.
  @override
  bool hasValidPayload(SdJwt data) {
    final context = data.payload[VcDataModelV2Key.context.key];
    return (context is List) &&
        context.contains(MutableVcDataModelV2.contextUrl);
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

    return _SdJwtDataModelV2.fromSdJwt(decode(input));
  }

  @override
  Map<String, dynamic> present(SdJwtDataModelV2 input) =>
      EnvelopedVcDm2Suite().present(input);

  /// Issues a new SD-JWT credential by signing the VC with the provided signer.
  ///
  /// [vc] - The credential to be issued.
  /// [signer] - The DID signer used to sign the credential.
  /// [options] - Optional configuration for the SD-JWT issuance.
  ///
  /// Returns a parsed SD-JWT credential with appropriate signatures and disclosures.
  ///
  /// Throws [SsiException] if the credential is invalid or if signing fails.
  @override
  Future<SdJwtDataModelV2> issue(
    MutableVcDataModelV2 vc,
    DidSigner signer, {
    SdJwtDm2Options? options,
  }) async {
    // Validate the credential
    _validateCredential(vc);

    final payload = vc.toJson();

    payload[VcDataModelV2Key.issuer.key] = signer.did;

    final jwtClaims = <String, dynamic>{};
    jwtClaims.addAll(payload);
    final disclosureFrame =
        options?.disclosureFrame ?? _getDefaultDisclosureFrame(payload);
    final jwtSigner = _createSdJwtSigner(signer);
    final handler = SdJwtHandlerV1();

    try {
      final sdJwt = handler.sign(
        claims: jwtClaims,
        disclosureFrame: disclosureFrame,
        signer: jwtSigner,
        hasher: options?.hasher ?? Base64EncodedOutputHasher.base64Sha256,
        holderPublicKey: options?.holderPublicKey,
      );
      return _SdJwtDataModelV2.fromSdJwt(await sdJwt);
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
  ///
  /// Returns true if the credential's signature is valid, false otherwise.
  @override
  Future<bool> verifyIntegrity(SdJwtDataModelV2 input) async {
    final algorithm =
        SignatureScheme.fromString(input.sdJwt.header['alg'] as String);

    final verifier = await SdJwtDidVerifier.create(
      algorithm: algorithm,
      kid: input.sdJwt.header['kid'] as String?,
      issuerDid: input.issuer.id,
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

  /// Validates the credential before issuing.
  ///
  /// [vc] - The credential to validate.
  ///
  /// Throws [SsiException] if any required fields are missing.
  void _validateCredential(MutableVcDataModelV2 vc) {
    final errors = <String>[];

    // Check required fields
    if (vc.context.isEmpty) {
      errors.add('Context is required');
    }

    if (vc.type.isEmpty) {
      errors.add('Type is required');
    }

    if (vc.issuer.isEmpty) {
      errors.add('Issuer is required');
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

/// Creates an SD-JWT signer from a DID signer.
///
/// [signer] - The DID signer to wrap.
///
/// Returns a Signer implementation for SD-JWT operations.
Signer _createSdJwtSigner(DidSigner signer) {
  return _DidSignerAdapter(signer);
}

/// Adapter to wrap the DidSigner for SD-JWT signing operations.
///
/// This adapter uses the synchronous signing method from DidSigner
/// to implement the Signer interface required by SD-JWT library.
class _DidSignerAdapter implements Signer {
  /// The wrapped DID signer.
  final DidSigner _didSigner;

  /// Creates a new adapter for the given DID signer.
  ///
  /// [_didSigner] - The DID signer to adapt.
  _DidSignerAdapter(this._didSigner);

  /// Gets the IANA algorithm name for the signature scheme.
  ///
  /// Returns the JWT algorithm name from the signature scheme,
  /// defaulting to ES256K if not available.
  @override
  String get algIanaName => _didSigner.signatureScheme.alg != null
      ? _didSigner.signatureScheme.alg!
      : 'ES256K'; // Default to ES256K if no JWT name is available

  /// Gets the key ID for the signing key.
  ///
  /// Returns the key ID from the wrapped DID signer.
  @override
  String? get keyId => _didSigner.keyId;

  /// Signs the input data using the synchronous sign method.
  ///
  /// [input] - The data to sign.
  ///
  /// Returns the signature as a byte array.
  @override
  Future<Uint8List> sign(Uint8List input) {
    return _didSigner.sign(input);
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
