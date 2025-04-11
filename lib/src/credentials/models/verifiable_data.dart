/// Cryptographically verifiable data
///
/// This will be the root representation for both VerifiableCredentials and VerifiablePresentations
abstract class VerifiableData {
  /// Returns the VerifiableCredential issuer
  List<String> get context;

  /// Returns the VerifiableCredential id.
  String? get id;

  /// Returns a list of VerifiableCredential types.
  // FIXME should be changed to a Set
  List<String> get type;

  /// Used by the mechanism to embed securing mechnism to verify the integrity of the verifiable data
  Map<String, dynamic> get proof;

  /// JSON representation of the Data Model
  Map<String, dynamic> toJson();

  /// Pareses "canonical" Data Model Json
  VerifiableData.fromJson(Map<String, dynamic> input);
}
