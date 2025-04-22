import '../../../types.dart';
import '../models/parsed_vp.dart';
import '../verification/vp_expiry_verifier.dart';
import '../verification/vp_integrity_verifier.dart';
import '../verification/vp_verifier.dart';

/// Allows verification of any supported VC encodings
final class UniversalPresentationVerifier {
  final List<VpVerifier> customVerifiers;

  static final List<VpVerifier> defaultVerifiers = List.unmodifiable(
    <VpVerifier>[
      VpExpiryVerifier(),
      VpIntegrityVerifier(),
    ],
  );

  UniversalPresentationVerifier({
    List<VpVerifier>? customVerifiers,
  }) : customVerifiers = customVerifiers ?? [];

  Future<VerificationResult> verify(ParsedVerifiablePresentation data) async {
    final errors = <String>[];
    final warnings = <String>[];

    for (final verifier in defaultVerifiers) {
      final result = await verifier.verify(data);
      errors.addAll(result.errors);
      warnings.addAll(result.warnings);
    }

    for (final customVerifier in customVerifiers) {
      var verifResult = await customVerifier.verify(data);
      errors.addAll(verifResult.errors);
      warnings.addAll(verifResult.warnings);
    }

    return VerificationResult.fromFindings(
      errors: errors,
      warnings: warnings,
    );
  }
}
