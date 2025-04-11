import '../../../ssi.dart';

mixin VerifiableCredentialExpiryVerification {
  Future<bool> verifyExpiry(VerifiableCredential data) async {
    var now = DateTime.now();
    var validFrom = data.validFrom;
    var validUntil = data.validUntil;

    if (validFrom != null && now.isBefore(validFrom)) {
      return false;
    }
    if (validUntil != null && now.isAfter(validUntil)) {
      return false;
    }

    return true;
  }
}
