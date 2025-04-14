/// Cryptographically verifiable data with embedded proof.
///
/// A class implementing this interface may use embedded proofs for
/// cryptographic verification. This interface marks that it's possible
/// to model an embedded proof within the data structure.
///
/// This is the root representation for both [VerifiableCredential] and
/// [VerifiablePresentation] types.
abstract interface class DocWithEmbeddedProof {
  /// The cryptographic proof used to verify the integrity of this data.
  ///
  /// If the map is empty, no embedded proof is present.
  Map<String, dynamic> get proof;

  /// Converts this document to a JSON-serializable map.
  Map<String, dynamic> toJson();
}
