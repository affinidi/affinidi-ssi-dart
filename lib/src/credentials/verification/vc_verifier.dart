import '../../types.dart';
import '../models/parsed_vc.dart';

/// Interface for verifying Verifiable Credentials (VCs).
abstract interface class VcVerifier {
  /// Verifies the given [vc] credential and returns a [VerificationResult].
  ///
  /// Implementations should validate specific aspects of the credential
  /// (e.g., expiration, proof signature) and report findings.
  Future<VerificationResult> verify(ParsedVerifiableCredential vc);
}
