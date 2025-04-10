import '../../types.dart';
import 'embedded_proof.dart';

abstract class EmbeddedProofSuite<SuiteOptions> {
  Future<EmbeddedProof> createProof(
    Map<String, dynamic> document,
    SuiteOptions options,
  );

  Future<VerificationResult> verifyProof(
    Map<String, dynamic> document,
  );

  static void verifyEmbeddedProof(Map<String, dynamic> vc) {
    // identitfy the right suite to use
  }
}
