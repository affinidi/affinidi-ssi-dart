import 'credential_schema.dart';
import 'credential_status.dart';
import 'credential_subject.dart';
import 'doc_with_embedded_proof.dart';
import 'holder.dart';
import 'issuer.dart';
import '../proof/embedded_proof.dart';
import 'vc_models.dart';

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
  // FIXME(FTL-20734) should be changed to a Set
  List<String> get type;

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
  CredentialSubject get credentialSubject;

  /// The schemas that define the structure of this credential.
  ///
  /// Returns empty list if not set.
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

  /// The entity that holds this credential.
  ///
  /// Returns null if not set.
  Holder? get holder;

  /// The cryptographic proof that makes this credential verifiable.
  EmbeddedProof get proof;

  /// Refreshing service for this credential.
  ///
  /// Returns null if not set.
  RefreshService? get refreshService;

  /// Terms of use associated with this credential.
  ///
  /// Returns empty list if not set.
  List<TermOfUse> get termsOfUse;

  /// Evidence supporting the claims in this credential.
  ///
  /// Returns empty list if not set.
  List<Evidence> get evidence;

  /// Converts this credential to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson();
}
