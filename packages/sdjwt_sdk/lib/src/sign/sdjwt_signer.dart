part of '../models/sdjwt.dart';

/// Input class for the SD-JWT signing process.
///
/// Contains all the necessary information to create a signed SD-JWT.
class SdJwtSignerInput {
  /// The original claims to be included in the JWT.
  final Map<String, dynamic> claims;

  /// A frame specifying which claims should be selectively disclosable.
  final Map<String, dynamic> disclosureFrame;

  /// The private key of the issuer used to sign the JWT.
  final Signer signer;

  /// The hasher used for creating disclosure digests.
  final Hasher<String, String> hasher;

  /// The public key of the holder, used for key binding.
  final SdPublicKey? holderPublicKey;

  /// The JWT header [typ] for this SD-JWT. Defaults to `sd+jwt`.
  final String typ;

  /// Creates a new input for the SD-JWT signing process.
  ///
  /// Parameters:
  /// - **[claims]**: The original claims to be included in the JWT.
  /// - **[disclosureFrame]**: A frame specifying which claims should be selectively disclosable.
  /// - **[signer]**: The [Signer] of the issuer used to sign the JWT.
  /// - **[hasher]**: The [Hasher] for creating disclosure digests.
  /// - **[holderPublicKey]**: The public key of the holder, used for key binding.
  SdJwtSignerInput(
      {required this.claims,
      required this.disclosureFrame,
      required this.signer,
      required this.hasher,
      this.holderPublicKey,
      this.typ = 'sd+jwt'});
}

/// Signer class for creating Selective Disclosure JWTs (SD-JWTs).
///
/// This class implements the logic for creating SD-JWTs with selectively
/// disclosable claims according to the SD-JWT specification.
class SdJwtSigner extends Action<SdJwtSignerInput, SdJwt> with JwtSigner {
  /// @internal
  /// Extractor for confirmation claims, not intended for direct use
  final _cnfExtractor = CnfExtractor();

  @override
  SdJwt execute(SdJwtSignerInput input) {
    if (input.claims.isEmpty) {
      throw ArgumentError('`claims` cannot be empty');
    }
    final disclosures = <Disclosure>{};
    final Map<String, dynamic> sdClaims = jsonDecode(jsonEncode(input.claims));
    final claimProcessorInput = ClaimProcessorInput(
        sdClaims, input.disclosureFrame, disclosures, input.hasher);
    ClaimProcessor().execute(claimProcessorInput);
    sdClaims['_sd_alg'] = input.hasher.name;
    if (input.holderPublicKey != null) {
      sdClaims['cnf'] = _cnfExtractor.execute(input.holderPublicKey!);
    }

    final String token = generateSignedCompactJwt(
        signer: input.signer,
        claims: sdClaims,
        protectedHeaders: {'typ': input.typ});

    final signedToken = SdJwt._fromParts(
        jwsToken: token,
        disclosures: disclosures,
        payload: sdClaims,
        hasher: input.hasher);

    signedToken._verified._isJwsVerified = true;

    return signedToken;
  }
}
