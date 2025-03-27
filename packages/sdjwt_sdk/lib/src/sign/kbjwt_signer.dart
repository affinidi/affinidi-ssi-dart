part of '../models/sdjwt.dart';

/// Input class for the Key Binding JWT signing process.
///
/// Contains all the necessary information to create a signed KB-JWT.
class KbJwtSignerInput {
  /// The SD-JWT token to bind the key to.
  final SdJwt sdJwtToken;

  /// The set of disclosures to include in the presentation.
  final Set<Disclosure> disclosuresToKeep;

  /// The audience for the KB-JWT.
  final String audience;

  /// The JWT signer for signing the KB-JWT. This should be the holder's signer.
  final Signer signer;

  /// The public Key of the holder used to verify if the SdJwt has `cnf` matching this public Key.
  final SdPublicKey? holderPublicKey;

  /// Creates a new input for the Key Binding JWT signing process.
  ///
  /// Parameters:
  /// - **[sdJwtToken]**: The SD-JWT token to bind the key to.
  /// - **[disclosuresToKeep]**: The set of disclosures to include in the presentation.
  /// - **[audience]**: The audience for the KB-JWT.
  /// - **[signer]**: The [Signer] used to sign the KB-JWT.
  /// - **[holderPublicKey]**: The public key of the holder.
  KbJwtSignerInput(
      {required this.sdJwtToken,
      required this.disclosuresToKeep,
      required this.audience,
      required this.signer,
      this.holderPublicKey});
}

/// Signer class for creating Key Binding JWTs (KB-JWTs).
///
/// This class implements the logic for creating KB-JWTs that bind
/// an SD-JWT to a specific holder key, preventing unauthorized presentations.
class KbJwtSigner extends Action<KbJwtSignerInput, SdJwt> with JwtSigner {
  /// Validator for the KB-JWT signer input.
  final _validator = AsyncKbJwtSignerInputValidator();

  /// Calculator for base64 digests.
  final _hashCalculator = Base64DigestCalculator();

  /// Generator for secure nonces.
  final _b64nonceGenerator = Base64NonceGenerator();

  @override
  SdJwt execute(KbJwtSignerInput input) {
    _validator.execute(input);

    final sdJwt = input.sdJwtToken;

    final derivedSdJwt = sdJwt.withDisclosures(input.disclosuresToKeep);
    final sdHash = _hashCalculator.execute(derivedSdJwt);

    final Map<String, dynamic> claims = {
      'iat': jwtNow(),
      'aud': input.audience,
      'nonce': _b64nonceGenerator.generate(),
      'sd_hash': sdHash
    };

    final String kbJwt = generateSignedCompactJwt(
        signer: input.signer,
        claims: claims,
        protectedHeaders: {'typ': 'kb+jwt'});

    final signedSdPlusKbToken = derivedSdJwt.withKbJwt(kbJwt);
    signedSdPlusKbToken._verified._isKbJwtVerified = true;

    return signedSdPlusKbToken;
  }
}
