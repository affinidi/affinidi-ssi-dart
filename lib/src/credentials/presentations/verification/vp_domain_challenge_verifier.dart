import 'package:ssi/src/types.dart';

import '../models/parsed_vp.dart';
import 'vp_verifier.dart';

/// A verifier that checks domain and challenge are valid in proof
///
/// Delegates verification to [VpDomainChallengeVerifier]
///
///
/// Example:
/// ```dart
/// final verifier = VpDomainChallengeVerifier(challenge: 'your-challenge', domain: ['your-domain.com']);
/// final result = await verifier.verify(vp);
/// if (!result.isValid) {
///   print("Presentation contains invalid domain or challenge");
/// }
/// ```
class VpDomainChallengeVerifier implements VpVerifier {
  /// Domain against which vp need to be verified
  final List<String>? domain;

  /// Challenge against which vp need to be verified
  final String? challenge;

  /// Creates a [VpDomainChallengeVerifier].
  VpDomainChallengeVerifier({
    this.domain,
    this.challenge,
  });

  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation data) async {
    if (data.proof.isEmpty) {
      // proof is not present then return success
      return VerificationResult.ok();
    }

    for (final proof in data.proof) {
      final proofDomain = proof.domain;
      final proofChallenge = proof.challenge;

      if (proofDomain != null) {
        var isDomainValid = proofDomain.every((d) =>
            d.trim().isNotEmpty && domain != null ? domain!.contains(d) : true);

        if (!isDomainValid) {
          return VerificationResult.invalid(
              errors: ['invalid or missing proof.domain']);
        }

        if (proofChallenge == null || proofChallenge.trim().isEmpty) {
          return VerificationResult.invalid(
              errors: ['invalid or missing proof.challenge']);
        }

        if (challenge != null && proofChallenge != challenge) {
          return VerificationResult.invalid(
              errors: ['invalid or missing proof.challenge']);
        }
      } else if (proofChallenge != null) {
        return VerificationResult.invalid(
            errors: ['proof.challenge must be accompanied by proof.domain']);
      }
    }

    return VerificationResult.ok();
  }
}
