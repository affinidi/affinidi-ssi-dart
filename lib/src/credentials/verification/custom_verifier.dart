import '../../../ssi.dart';

abstract class CustomVerifier {
  Future<VerificationResult> verify(VerifiableCredential vc);
}
