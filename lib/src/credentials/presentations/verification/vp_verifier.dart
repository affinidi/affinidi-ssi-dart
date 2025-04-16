import '../../../../ssi.dart';
import '../models/parsed_vp.dart';

abstract interface class VpVerifier {
  Future<VerificationResult> verify(ParsedVerifiablePresentation vc);
}
