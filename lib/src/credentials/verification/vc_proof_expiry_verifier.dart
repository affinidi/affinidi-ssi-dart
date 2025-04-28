import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../models/parsed_vc.dart';
import '../suites/vc_suites.dart';
import 'vc_verifier.dart';

/// A verifier that checks expiry of the proof if it present
///
/// Delegates verification to [VcProofExpiryVerifier]
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
class VcProofExpiryVerifier implements VcVerifier {
  final DateTime Function() _getNow;

  /// Creates a [VcProofExpiryVerifier].
  VcProofExpiryVerifier({
    DateTime Function() getNow = DateTime.now,
  }) : _getNow = getNow;

  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential data) async {
    final vcSuite = VcSuites.getVcSuite(data);

    var proofExpiryValid = false;

    try {
      proofExpiryValid = await vcSuite.verifyProofExpiry(data, getNow: _getNow);
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

    return Future.value(
      VerificationResult.ok(),
    );
  }
}
