// ignore_for_file: depend_on_referenced_packages

import 'package:sdjwt_sdk/sdjwt_sdk.dart';
import 'package:sdjwt_sdk/src/api.dart';
import 'package:sdjwt_sdk/src/models/sdjwt.dart';

/// Implementation of the [SdJwtHandler] interface.
///
/// This class provides implementations for signing and verifying
/// Selective Disclosure JWTs according to the SD-JWT specification.
class SdJwtHandlerV1 implements SdJwtHandler {
  @override
  SdJwt sign({
    required Map<String, dynamic> claims,
    required Map<String, dynamic> disclosureFrame,
    required Signer signer,
    Hasher<String, String>? hasher,
    SdPublicKey? holderPublicKey,
  }) {
    final input = SdJwtSignerInput(
        claims: claims,
        disclosureFrame: disclosureFrame,
        signer: signer,
        hasher: hasher ?? Base64EncodedOutputHasher.base64Sha256,
        holderPublicKey: holderPublicKey);
    final sdJwtSigner = SdJwtSigner();
    return sdJwtSigner.execute(input);
  }

  @override
  SdJwt verify(
      {required SdJwt sdJwt,
      required Verifier verifier,
      bool verifyKeyBinding = false}) {
    final SdJwtVerifyAction sdJwtVerifier = SdJwtVerifyAction();
    final input = SdJwtVerifierInput(
        config: {'verifyKeyBinding': verifyKeyBinding},
        sdJwt: sdJwt,
        verifier: verifier);

    return sdJwtVerifier.execute(input);
  }

  @override
  SdJwt decodeAndVerify(
      {required String sdJwtToken,
      required Verifier verifier,
      CustomHasher? customHasher,
      bool verifyKeyBinding = false}) {
    final sdJwt = unverifiedDecode(sdJwtToken: sdJwtToken);
    return verify(
        sdJwt: sdJwt, verifier: verifier, verifyKeyBinding: verifyKeyBinding);
  }

  @override
  SdJwt unverifiedDecode(
      {required String sdJwtToken, CustomHasher? customHasher}) {
    return SdJwt.parse(sdJwtToken, customHasher: customHasher);
  }

  @override
  SdJwt present(
      {required SdJwt sdJwt,
      required Set<Disclosure> disclosuresToKeep,
      PresentWithKbJwtInput? presentWithKbJwtInput}) {
    if (presentWithKbJwtInput != null) {
      final input = KbJwtSignerInput(
          sdJwtToken: sdJwt,
          disclosuresToKeep: disclosuresToKeep,
          audience: presentWithKbJwtInput.audience,
          holderPublicKey: presentWithKbJwtInput.holderPublicKey,
          signer: presentWithKbJwtInput.signer);
      final kbJwtSigner = KbJwtSigner();
      return kbJwtSigner.execute(input);
    } else {
      return sdJwt.withDisclosures(disclosuresToKeep);
    }
  }
}
