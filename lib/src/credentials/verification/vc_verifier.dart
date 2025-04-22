import '../../types.dart';
import '../models/parsed_vc.dart';

abstract interface class VcVerifier {
  Future<VerificationResult> verify(ParsedVerifiableCredential vc);
}
