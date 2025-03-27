// ignore_for_file: constant_identifier_names, depend_on_referenced_packages

import 'package:sdjwt_sdk/sdjwt_sdk.dart';

/// Represents the additional arguments needed to enable presenting the SdJwt with a signed KbJwt.
interface class PresentWithKbJwtInput {
  /// The verifier who we will be presenting to, so that the kbJwt is bound to that specific presentation.
  final String audience;

  /// The signer for the kbJwt. this should be the signer for the holder.
  final Signer signer;

  /// the holder's public key which corresponds to the above Signer.
  /// It should also be the same as the `cnf` mentioned within the sdJwt.
  /// This establishes the holder binding:
  ///     - The holder is the same as the presenter
  ///     - The holder is also the same holder the sdJwt was issued to
  final SdPublicKey holderPublicKey;

  /// Creates the input for enabling kbJwt signed presentation
  ///
  /// Parameters:
  /// - **[audience]** (required): The verifier who we will be presenting to.
  /// - **[signer]** (required): The signer for the kbJwt.
  /// - **[holderPublicKey]** (required): The public key that corresponds to the [signer].
  PresentWithKbJwtInput(this.audience, this.signer, this.holderPublicKey);
}

/// An abstract class that provides functionalities for
/// Selective Disclosure JWTs (SD-JWT) like: Signing, KeyBinding Signing and
/// Verification.
abstract class SdJwtHandler {
  /// Signs the given claims and disclosures using the issuer private key and
  /// hashing algorithm.
  ///
  /// Parameters:
  /// - **[claims]** (required): A JSON object containing the original claims to be
  ///  signed.
  /// - **[disclosureFrame]** (required): A JSON object defining which claims should
  ///  be disclosed and which not.
  /// - **[Signer]** (required): The Signer configured with the private key of the issuer to
  /// sign the SD-JWT.
  /// - **[hasher]** (optional, defaults to SHA-256): The hasher used for creating
  /// disclosure digests in base64 format.
  /// - **[holderPublicKey]** (optional) : The public key of the holder used in case
  ///  of key binding singing.
  /// Returns:
  /// - A typed signed sd-jwt with the disclosures.
  ///
  /// Example:
  /// ```dart
  /// final SdJwtHandler handler = SdJwtHandlerV1();
  ///
  /// final claims = {
  ///   "first_name": "Alice",
  ///   "last_name": "Smith",
  ///   "email": "alice.smith@example.com"
  /// };
  ///
  /// final disclosureFrame = {
  ///   "_sd": ["first_name", "email"]
  /// };
  ///
  /// final sdJwt = await handler.sign(
  ///   claims: claims,
  ///   disclosureFrame: disclosureFrame,
  ///   signer: signer,
  /// );
  /// ```
  SdJwt sign({
    required Map<String, dynamic> claims,
    required Map<String, dynamic> disclosureFrame,
    required Signer signer,
    Hasher<String, String>? hasher,
    SdPublicKey? holderPublicKey,
  });

  /// Presents an existing SD-JWT with a subset set of it's disclosures optionally with
  /// key binding (KB-JWT) signed using the holder’s keys.
  ///
  /// Parameters:
  /// - **[sdJwt]** (required): The SD-JWT that needs to be key-bound.
  /// - **[disclosuresToKeep]** (required): Set of disclosures to retain.
  /// - **[presentWithKbJwtInput]** (optional): Value when kbJwt has to be added to the presented KbJwt.
  ///
  /// Returns:
  /// - A typed sd-jwt with the disclosures optionally with signed key-binding.
  ///
  /// Example:
  /// ```dart
  /// final SdJwtHandler handler = SdJwtHandlerV1();
  ///
  /// final claims = {
  ///   "first_name": "Alice",
  ///   "last_name": "Smith",
  ///   "email": "alice.smith@example.com"
  /// };
  ///
  /// final disclosureFrame = {
  ///   "_sd": ["first_name", "email"]
  /// };
  ///
  /// final sdJwt = await handler.sign(
  ///   claims: claims,
  ///   disclosureFrame: disclosureFrame,
  ///   signer: signer,
  /// );
  ///
  /// final disclosuresToKeep = sdJwt.sdJwtToken.disclosures;
  ///
  /// final sdJwtWithKeyBinding = await handler.present(
  ///   sdJwt: sdJwt,
  ///   disclosuresToKeep: disclosuresToKeep,
  ///   presentWithKbJwtInput: PresentWithKbJwtInput(
  ///     "https://verifier.example.com",
  ///     signer,
  ///     holderPublicKey
  ///   ),
  /// );
  /// ```
  SdJwt present(
      {required SdJwt sdJwt,
      required Set<Disclosure> disclosuresToKeep,
      PresentWithKbJwtInput? presentWithKbJwtInput});

  /// Verifies the provided SD-JWT.
  ///
  /// Parameters:
  /// - **[sdJwt]** (required): The [SdJwt] to be verified.
  /// - **[verifier]** (required): The verifier with access to issuer's public key.
  ///
  /// Returns:
  /// - The [SdJwt].
  ///
  /// Example:
  /// ```dart
  /// final sdJwt = await handler.sign(
  ///   claims: claims,
  ///   disclosureFrame: selectiveDisclosureClaims,
  ///   signer: signer,
  /// );
  ///
  ///
  /// final publicKeyFile = File(path.join(
  ///   resourcesPath,
  ///   'test_public_key.pem',
  /// ));
  ///
  /// final publicKey = SdPublicKey(
  ///   publicKeyFile.readAsStringSync(),
  ///   SdJwtAlgorithm.es256k,
  /// );
  ///
  /// final verifier = SDKeyVerifier(publicKey);
  ///
  /// final verified = await handler.verify(
  ///   sdJwt: sdJwt,
  ///   verifier: verifier,
  /// );
  /// ```
  SdJwt verify(
      {required SdJwt sdJwt,
      required Verifier verifier,
      bool verifyKeyBinding = false});

  /// Decodes a serialized [SdJwt] and verifies it.
  ///
  /// Parameters:
  /// - **[sdJwtToken]** (required): The serialized [SdJwt] string.
  /// - **[verifier]** (required): The verifier with access to issuer's public key.
  ///
  /// Returns:
  /// - The [SdJwt].
  ///
  /// Example:
  /// ```dart
  /// final sdJwt = await handler.sign(
  ///   claims: claims,
  ///   disclosureFrame: selectiveDisclosureClaims,
  ///   signer: signer,
  /// );
  ///
  ///
  /// final publicKeyFile = File(path.join(
  ///   resourcesPath,
  ///   'test_public_key.pem',
  /// ));
  ///
  /// final publicKey = SdPublicKey(
  ///   publicKeyFile.readAsStringSync(),
  ///   SdJwtAlgorithm.es256k,
  /// );
  ///
  /// final verifier = SDKeyVerifier(publicKey);
  ///
  /// final verified = await handler.decodeAndVerify(
  ///   sdJwtToken: sdJwt.serialized,
  ///   verifier: verifier,
  /// );
  /// ```
  SdJwt decodeAndVerify(
      {required String sdJwtToken,
      required Verifier verifier,
      CustomHasher? customHasher,
      bool verifyKeyBinding = false});

  /// Decodes a serialized [SdJwt] without verifying it.
  ///
  /// Parameters:
  /// - **[sdJwtToken]** (required): The serialized [SdJwt] string.
  ///
  /// Returns:
  /// - The parsed [SdJwt].
  ///
  /// Example:
  /// ```dart
  /// final sdJwt = await handler.sign(
  ///   claims: claims,
  ///   disclosureFrame: selectiveDisclosureClaims,
  ///   signer: signer,
  /// );
  ///
  /// final verified = await handler.unverifiedDecode(
  ///   sdJwtToken: sdJwt.serialized
  /// );
  /// ```
  SdJwt unverifiedDecode(
      {required String sdJwtToken, CustomHasher? customHasher});
}
