import 'package:ssi/src/credentials/models/verifiable_credential.dart';

abstract class VcDataModelVerifier {
  /// check if the [data] provided is expired or not
  Future<bool> verifyExpiry(VerifiableCredential data) async {
    DateTime now = DateTime.now();
    DateTime? validFrom = data.validFrom;
    DateTime? validUntil = data.validUntil;

    if (validFrom != null && now.isBefore(validFrom)) {
      return false;
    }
    if (validUntil != null && now.isAfter(validUntil)) {
      return false;
    }

    return true;
  }

  /// check integrity verification of [data]
  Future<bool> verifyIntegrity(VerifiableCredential data);
}
