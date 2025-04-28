import 'package:ssi/src/types.dart';

import '../models/parsed_vp.dart';
import 'vp_verifier.dart';

/// A verifier that checks expiry of the proof if it present
///
/// Delegates verification to [VpProofExpiryVerifier]
///
///
/// Example:
/// ```dart
/// final verifier = VpProofExpiryVerifier();
/// final result = await verifier.verify(vp);
/// if (!result.isValid) {
///   print("Presentation contains expired proof");
/// }
/// ```
class VpProofExpiryVerifier implements VpVerifier {
  final DateTime Function() _getNow;

  /// Creates a [VpProofExpiryVerifier].
  VpProofExpiryVerifier({
    DateTime Function() getNow = DateTime.now,
  }) : _getNow = getNow;

  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation data) async {
    if (data.proof.isEmpty) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof'],
      );
    }
    var now = _getNow();
    for (final proof in data.proof) {
      final expires = proof.expires;
      if (expires != null && now.isAfter(expires)) {
        return VerificationResult.invalid(errors: ['proof is no longer valid']);
      }
    }

    return VerificationResult.ok();
  }
}
