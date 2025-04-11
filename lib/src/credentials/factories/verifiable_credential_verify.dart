import '../../../ssi.dart';
import '../models/parsed_vc.dart';
import '../verification/integrity_verifier.dart';
import '../verification/vc_expiry_verifier.dart';
import '../verification/vc_verifier.dart';

final class CredentialVerifier {
  final List<VcVerifier> customVerifiers;

  static final List<VcVerifier> defaultVerifiers = List.unmodifiable(
    <VcVerifier>[
      VcExpiryVerifier(),
      VcIntegrityVerifier(),
    ],
  );

  //FIXME add limit to types supported
  CredentialVerifier({
    List<VcVerifier>? customVerifier,
  }) : customVerifiers = customVerifier ?? [];

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
