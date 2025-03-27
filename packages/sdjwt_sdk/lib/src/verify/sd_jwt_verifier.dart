part of '../models/sdjwt.dart';

/// Input class for the SD-JWT verification process.
///
/// Contains all the necessary information to verify an SD-JWT.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class SdJwtVerifierInput {
  /// Configuration options for the verification process.
  final Map<String, dynamic> config;

  /// The SD-JWT to verify.
  final SdJwt sdJwt;

  /// The public key of the issuer used to verify the JWT signature.
  final Verifier verifier;

  /// Creates a new input for the SD-JWT verification process.
  ///
  /// Parameters:
  /// - **[config]**: Configuration options for the verification process.
  /// - **[sdJwt]**: The SD-JWT to verify.
  /// - **[verifier]**: The [Verifier] with issuer's public key used to verify the JWT signature.
  SdJwtVerifierInput(
      {required this.config, required this.sdJwt, required this.verifier});
}

/// Action class for verifying Selective Disclosure JWTs (SD-JWTs).
///
/// This class implements the logic for verifying SD-JWTs and their
/// selectively disclosed claims according to the SD-JWT specification.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class SdJwtVerifyAction extends Action<SdJwtVerifierInput, SdJwt>
    with JwtVerifier {
  /// Action for verifying Key Binding JWTs.
  final KbVerifyAction _kbVerifyAction;

  /// Creates a new action for verifying SD-JWTs.
  ///
  /// Parameters:
  /// - **[kbVerifyAction]**: Action for verifying Key Binding JWTs.
  SdJwtVerifyAction({KbVerifyAction? kbVerifyAction})
      : _kbVerifyAction = kbVerifyAction ?? KbVerifyAction();

  @override
  SdJwt execute(SdJwtVerifierInput input) {
    final sdJwt = input.sdJwt;

    try {
      verifyJwt(
        serialized: sdJwt.jwsString,
        verifier: input.verifier,
      );
      sdJwt._verified._isJwsVerified = true;
    } catch (e) {
      sdJwt._verified._isJwsVerified = false;
      return sdJwt;
    }

    // Verify holder KB JWT (if configured)
    final shouldVerifyKb = input.config['verifyKeyBinding'] ?? false;

    if (shouldVerifyKb) {
      try {
        final kbResult = _kbVerifyAction.execute(sdJwt);
        if (!kbResult) {
          throw Exception('Invalid KB JWT');
        }

        sdJwt._verified._isKbJwtVerified = true;
      } catch (e) {
        sdJwt._verified._isKbJwtVerified = false;
        return sdJwt;
      }
    }

    return sdJwt;
  }
}
