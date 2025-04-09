import 'embedded_proof.dart';

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

  static verifyEmbeddedProof(Map<String, dynamic> vc) {
    // identitfy the right suite to use
  }
}
