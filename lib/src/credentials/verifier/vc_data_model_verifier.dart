import 'package:ssi/src/credentials/models/verifiable_credential.dart';

abstract class VcDataModelVerifier {
  /// check if the [data] provided is expired or not
  bool checkExpiry(VerifiableCredential data) {
    DateTime now = DateTime.now();
    if (data.validFrom != null && data.validUntil != null) {
      DateTime? validFrom = data.validFrom;
      DateTime? validUntil = data.validUntil;

      return (now.isBefore(validFrom!) || now.isAfter(validUntil!));
    }
    return false;
  }

  /// check integrity verification of [data]
  bool checkIntegrityVerification(Object data);
}
