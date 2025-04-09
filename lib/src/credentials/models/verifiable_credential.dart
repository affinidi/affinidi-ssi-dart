import 'credential_schema.dart';

/// A tamper-evident credential whose authorship can be cryptographically verified.
///
/// Verifiable credentials can be used to build verifiable presentations, which can also be cryptographically verifiable.
abstract interface class VerifiableCredential<RawDataType> {
  /// Returns the VerifiableCredential issuer
  List<String> get context;

  /// Returns the VerifiableCredential issuer.
  // FIXME issuer can be an entity with an id or a string
  String get issuer;

  /// Returns a list of VerifiableCredential types.
  // FIXME should be changed to a Set
  List<String> get type;

  /// Returns a Map representing the VerifiableCredential Subject.
  ///
  /// Example of a VerifiableCredential Subject:<br/>
  /// ```
  /// {
  ///   "id": "name",
  ///   "name": "John Doe",
  /// }
  /// ```
  Map<String, dynamic> get credentialSubject;

  /// Returns the VerifiableCredential id.
  String get id;

  /// Returns a list of VerifiableCredential schema.
  ///
  /// Returns null if not set.
  ///
  /// See [CredentialSchema] for more details.
  List<CredentialSchema> get credentialSchema;

  /// Returns the date when the VerifiableCredential was issued.
  DateTime? get validFrom;

  /// Returns the VerifiableCredential expiry date.
  ///
  /// Returns null if not set
  DateTime? get validUntil;

  /// Returns a json representation of the original data provided to create the VerifiableCredential
  Map<String, dynamic> toJson();

  /// Returns the original input provided to create the VerifiableCredential
  RawDataType get rawData;
}
