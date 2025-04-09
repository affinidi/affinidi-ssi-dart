import 'package:ssi/src/credentials/proof/embedded_proof_suite.dart';
import 'package:ssi/ssi.dart';

abstract class CustomVerifier {
  Future<VerificationResult> verify(VerifiableCredential vc);
}
