import 'verification_relationship.dart';

/// The result of adding a key to a DID controller.
class AddVerificationMethodResult {
  /// The primary verification method ID created for the key.
  final String verificationMethodId;

  /// A map of verification relationships to their corresponding verification
  /// method IDs. Note that for some relationships (like `keyAgreement` with
  /// an `ed25519` key), the ID might be different from the primary one.
  final Map<VerificationRelationship, String> relationships;

  /// Creates a new [AddVerificationMethodResult] instance.
  AddVerificationMethodResult({
    required this.verificationMethodId,
    required this.relationships,
  });
}
