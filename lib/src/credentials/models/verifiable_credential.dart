import 'credential_schema.dart';
import 'credential_status.dart';
import 'doc_with_embedded_proof.dart';

/// A tamper-evident credential whose authorship can be cryptographically verified.
///
/// Verifiable credentials can be used to build verifiable presentations,
/// which can also be cryptographically verifiable.
abstract interface class VerifiableCredential implements DocWithEmbeddedProof {
  /// The context defining the schema for this credential.
  List<String> get context;

  /// The unique identifier for this credential.
  String? get id;

  /// The types describing the structure of this credential.
  // FIXME should be changed to a Set
  List<String> get type;

  /// The entity that issued this credential.
  // FIXME issuer can be an entity with an id or a string
  String get issuer;

  /// The subject data contained in this credential.
  ///
  /// Example of a credential subject:
  /// ```
  /// {
  ///   "id": "did:example:123",
  ///   "name": "John Doe",
  /// }
  /// ```
  Map<String, dynamic> get credentialSubject;

  /// The schemas that define the structure of this credential.
  ///
  /// Returns null if not set.
  ///
  /// See [CredentialSchema] for more details.
  List<CredentialSchema> get credentialSchema;

  /// The status information for this credential.
  ///
  /// Returns null if not set.
  ///
  /// See [CredentialStatus] for more details.
  CredentialStatus? get credentialStatus;

  /// The date when this credential was issued.
  DateTime? get validFrom;

  /// The date when this credential expires.
  ///
  /// Returns null if the credential does not expire.
  DateTime? get validUntil;

  /// Converts this credential to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson();
}
