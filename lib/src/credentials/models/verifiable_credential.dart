import 'doc_with_embedded_proof.dart';
import 'field_types/credential_schema.dart';
import 'field_types/credential_subject.dart';
import 'field_types/issuer.dart';
import 'field_types/terms_of_use.dart';

/// A tamper-evident credential whose authorship can be cryptographically verified.
///
/// Verifiable credentials can be used to build verifiable presentations,
/// which can also be cryptographically verifiable.
abstract interface class VerifiableCredential implements DocWithEmbeddedProof {
  /// The context defining the schema for this credential.
  List<String> get context;

  /// The unique identifier for this credential.
  Uri? get id;

  /// The types describing the structure of this credential.
  Set<String> get type;

  /// The entity that issued this credential.
  Issuer get issuer;

  /// The subject data contained in this credential.
  ///
  /// Example of a credential subject:
  /// ```
  /// {
  ///   "id": "did:example:123",
  ///   "name": "John Doe",
  /// }
  /// ```
  List<CredentialSubject> get credentialSubject;

  /// The schemas that define the structure of this credential.
  ///
  /// Returns empty list if not set.
  ///
  /// See [MutableCredentialSchema] for more details.
  List<CredentialSchema> get credentialSchema;

  /// The date when this credential was issued.
  DateTime? get validFrom;

  /// The date when this credential expires.
  ///
  /// Returns null if the credential does not expire.
  DateTime? get validUntil;

  /// Returns null if the credential does not have terms of use.
  List<TermsOfUse> get termsOfUse;

  /// Converts this credential to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson();
}
