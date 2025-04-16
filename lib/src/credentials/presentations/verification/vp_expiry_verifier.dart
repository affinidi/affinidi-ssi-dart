import '../../../../ssi.dart';
import '../../verification/vc_expiry_verifier.dart';
import '../models/parsed_vp.dart';
import 'vp_verifier.dart';

class VpExpiryVerifier implements VpVerifier {
  final VcExpiryVerifier _vcExpiryVerifier;

  VpExpiryVerifier({
    DateTime Function() getNow = DateTime.now,
  }) : _vcExpiryVerifier = VcExpiryVerifier(getNow: getNow);

  @override
  Future<VerificationResult> verify(ParsedVerifiablePresentation data) async {
    for (final credential in data.verifiableCredential) {
      final expiryVerification = await _vcExpiryVerifier.verify(credential);

      if (!expiryVerification.isValid) {
        return expiryVerification;
      }
    }

    return Future.value(
      VerificationResult.ok(),
    );
  }
}
