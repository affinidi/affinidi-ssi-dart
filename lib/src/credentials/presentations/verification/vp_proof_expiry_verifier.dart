import 'package:ssi/src/types.dart';

import '../../../../ssi.dart';
import '../../verification/vc_proof_expiry_verifier.dart';
import '../models/parsed_vp.dart';
import '../suites/vp_suites.dart';
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
    final vpSuite = VpSuites.getVpSuite(data);

    var proofExpiryValid = false;

    try {
      proofExpiryValid = await vpSuite.verifyProofExpiry(data, getNow: _getNow);
    } catch (e) {
      proofExpiryValid = false;
    }

    if (!proofExpiryValid) {
      return Future.value(
        VerificationResult.invalid(
          errors: [SsiExceptionType.failedIntegrityVerification.code],
        ),
      );
    }

    for (final credential in data.verifiableCredential) {
      var vcProofExpiry =
          await VcProofExpiryVerifier(getNow: _getNow).verify(credential);

      if (!vcProofExpiry.isValid) {
        return vcProofExpiry;
      }
    }

    return Future.value(
      VerificationResult.ok(),
    );
  }
}
