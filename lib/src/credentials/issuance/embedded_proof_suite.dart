import 'package:ssi/src/credentials/issuance/embedded_proof.dart';

abstract class VerificationResult {
  bool get isValid;
}

abstract class EmbeddedProofSuite<SuiteOptions> {
  Future<EmbeddedProof> createProof(
    Map<String, dynamic> document,
    SuiteOptions options,
  );

  Future<VerificationResult> verifyProof(Map<String, dynamic> document);
}
