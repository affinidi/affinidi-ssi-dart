/// Cryptographically verifiable data with embedded proof
///
/// A class implementing this does not have to use embedded proofs, this
/// interface only marks that it's possible to model embbedded proof.
///
/// This will be the root representation for both [VerifiableCredentials] and [VerifiablePresentations]
abstract class DocWithEmbeddedProof {
  /// Used by the mechanism to embed securing mechanism to verify the integrity of the verifiable data
  ///
  /// If map is empty then no embedded proof is present
  Map<String, dynamic> get proof;

  /// JSON representation of the Data Model
  Map<String, dynamic> toJson();

  /// Pareses "canonical" Data Model Json
  DocWithEmbeddedProof.fromJson(Map<String, dynamic> input);
}
