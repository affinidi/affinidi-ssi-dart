import 'package:ssi/src/credentials/models/parsed_vc.dart';
import 'package:ssi/src/credentials/verification/vc_verifier.dart';
import 'package:ssi/src/types.dart';

class VcExpiryVerifier implements VcVerifier {
  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential data) {
    var now = DateTime.now();
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
