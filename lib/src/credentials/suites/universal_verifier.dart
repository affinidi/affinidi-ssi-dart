import '../../types.dart';
import '../models/parsed_vc.dart';
import '../verification/vc_expiry_verifier.dart';
import '../verification/vc_integrity_verifier.dart';
import '../verification/vc_verifier.dart';

/// Allows verification of any supported VC encodings
final class UniversalVerifier {
  final List<VcVerifier> customVerifiers;

  static final List<VcVerifier> defaultVerifiers = List.unmodifiable(
    <VcVerifier>[
      VcExpiryVerifier(),
      VcIntegrityVerifier(),
    ],
  );

  UniversalVerifier({
    List<VcVerifier>? customVerifiers,
  }) : customVerifiers = customVerifiers ?? [];

  Future<VerificationResult> verify(ParsedVerifiableCredential data) async {
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
