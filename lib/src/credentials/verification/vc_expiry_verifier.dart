import '../../../ssi.dart';
import '../models/parsed_vc.dart';
import 'vc_verifier.dart';

class VcExpiryVerifier implements VcVerifier {
  final DateTime Function() _getNow;

  VcExpiryVerifier({
    DateTime Function() getNow = DateTime.now,
  }) : _getNow = getNow;

  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential data) {
    var now = _getNow();
    var validFrom = data.validFrom;
    var validUntil = data.validUntil;

    if (validFrom != null && now.isBefore(validFrom)) {
      return Future.value(
        VerificationResult.invalid(
          errors: ['vc is not yet valid, validFrom: "$validFrom"'],
        ),
      );
    }
    if (validUntil != null && now.isAfter(validUntil)) {
      return Future.value(
        VerificationResult.invalid(
          errors: ['vc is no longer valid, validUntil: "$validUntil"'],
        ),
      );
    }

    return Future.value(
      VerificationResult.ok(),
    );
  }
}
