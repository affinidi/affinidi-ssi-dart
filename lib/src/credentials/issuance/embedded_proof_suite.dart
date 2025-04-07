import 'package:ssi/src/credentials/issuance/embedded_proof.dart';

class VerificationResult {
  final bool isValid;
  final List<String> issues;

  VerificationResult({
    required this.isValid,
    List<String>? issues,
  }) : issues = issues ?? [];
}

abstract class EmbeddedProofSuite<SuiteOptions> {
  Future<EmbeddedProof> createProof(
    Map<String, dynamic> document,
    SuiteOptions options,
  );

  Future<VerificationResult> verifyProof(
    Map<String, dynamic> document,
  );
}
