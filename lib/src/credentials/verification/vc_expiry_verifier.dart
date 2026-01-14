import '../../types.dart';
import '../models/parsed_vc.dart';
import 'vc_verifier.dart';

/// Verifier that checks the validity period of a Verifiable Credential (VC).
///
/// It verifies whether the current time falls within the credential's
/// `validFrom` and `validUntil` date range.
class VcExpiryVerifier implements VcVerifier {
  final DateTime Function() _getNow;

  /// Creates a [VcExpiryVerifier].
  ///
  /// Optionally accepts a [getNow] function to provide the current time,
  /// useful for testing or custom time validation scenarios.
  VcExpiryVerifier({
    DateTime Function() getNow = DateTime.now,
  }) : _getNow = getNow;

  /// Verifies that the [data] credential is currently valid based on its
  /// `validFrom` and `validUntil` timestamps.
  ///
  /// Returns a [VerificationResult] indicating validity or listing expiration errors.
  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential data) {
    var now = _getNow();
    var validFrom = data.validFrom;
    var validUntil = data.validUntil;

    if (validFrom != null && now.isBefore(validFrom)) {
      return Future.value(
        VerificationResult.invalid(
          errors: ['vc ${data.id} is not yet valid, validFrom: "$validFrom"'],
        ),
      );
    }
    if (validUntil != null && now.isAfter(validUntil)) {
      return Future.value(
        VerificationResult.invalid(
          errors: ['vc ${data.id} is no longer valid, validUntil: "$validUntil"'],
        ),
      );
    }

    return Future.value(
      VerificationResult.ok(),
    );
  }
}
