import '../../types.dart';
import '../models/parsed_vc.dart';

/// Interface for verifying Verifiable Credentials (VCs).
abstract interface class VcVerifier {
  /// Verifies a single [vc] and returns a [VerificationResult].
  Future<VerificationResult> verify(ParsedVerifiableCredential vc);
}
