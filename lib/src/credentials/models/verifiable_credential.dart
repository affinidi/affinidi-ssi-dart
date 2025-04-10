import 'package:ssi/src/credentials/models/verifiable_data.dart';

import 'credential_schema.dart';
import 'credential_status.dart';

/// A tamper-evident credential whose authorship can be cryptographically verified.
///
/// Verifiable credentials can be used to build verifiable presentations, which can also be cryptographically verifiable.
abstract interface class VerifiableCredential extends VerifiableData {
  /// Returns the VerifiableCredential issuer.
  // FIXME issuer can be an entity with an id or a string
  String get issuer;

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

  /// Returns a list of VerifiableCredential schema.
  ///
  /// Returns null if not set.
  ///
  /// See [CredentialSchema] for more details.
  List<CredentialSchema> get credentialSchema;

  /// Returns the VerifiableCredential status.
  ///
  /// Returns null if not set.
  ///
  /// See [CredentialStatus] for more details.
  CredentialStatus? get credentialStatus;

  /// Returns the date when the VerifiableCredential was issued.
  DateTime? get validFrom;

  /// Returns the VerifiableCredential expiry date.
  ///
  /// Returns null if not set
  DateTime? get validUntil;

  @override
  VerifiableCredential.fromJson(super.input) : super.fromJson();
}
