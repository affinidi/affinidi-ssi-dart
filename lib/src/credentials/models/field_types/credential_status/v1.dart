import '../../../../util/json_util.dart';

abstract interface class _CredentialStatusV1Interface {
  Uri? get id;
  String? get type;

  /// Converts this status to a JSON-serializable map.
  Map<String, dynamic> toJson();
}

/// Represents a Mutable Credential Status for verifiable credentials following W3C standards.
///
/// This specification defines the credentialStatus property for discovering information related
/// to the status of a verifiable credential, such as whether it is revoked or not.
/// It uses JSON Schema format to check status of credential.
///
/// Example:
/// ```dart
/// final credentialStatus = MutableCredentialStatusV1(
///   id: Uri.parse('test-credential-status-id'),
///   type: 'BitstringStatusListEntry',
///   revocationFields: {'revocationListIndex': '94567', 'revocationListCredential': 'https://pharma.example.com/credentials/status/3'},
/// );
/// ```
class MutableCredentialStatusV1 extends _CredentialStatusV1Interface {
  /// The URL of optional unique identifier for the credential status object.
  @override
  Uri? id;

  /// The schema type of credential status.
  @override
  String? type;

  /// Revocation-related fields stored as a generic map (e.g., statusPurpose, statusListIndex).
  Map<String, dynamic>? revocationFields;

  /// Creates a [MutableCredentialStatusV1] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  /// The [revocationFields] contains optional revocation-related fields to be included in JSON.
  MutableCredentialStatusV1({
    this.id,
    this.type,
    this.revocationFields,
  });

  /// Creates a [MutableCredentialStatusV1] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory MutableCredentialStatusV1.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getString(json, 'type');
    final revocationFields = Map<String, dynamic>.from(json)
      ..remove('id')
      ..remove('type');

    return MutableCredentialStatusV1(
      id: id,
      type: type,
      revocationFields: revocationFields.isEmpty ? null : revocationFields,
    );
  }

  @override
  Map<String, dynamic> toJson() => cleanEmpty({
        'id': id?.toString(),
        'type': type,
        if (revocationFields != null && revocationFields!.isNotEmpty)
          ...revocationFields!,
      });
}

/// Represents a Credential Status for verifiable credentials following W3C standards.
///
/// This specification defines the credentialStatus property for discovering information related
/// to the status of a verifiable credential, such as whether it is revoked or not.
/// It uses JSON Schema format to check status of credential.
///
/// Example:
/// ```dart
/// final credentialStatus = CredentialStatusV1(
///   id: Uri.parse('test-credential-status-id'),
///   type: 'BitstringStatusListEntry',
///   revocationFields: {'revocationListIndex': '94567', 'revocationListCredential': 'https://pharma.example.com/credentials/status/3'},
/// );
/// ```
class CredentialStatusV1 extends _CredentialStatusV1Interface {
  final Uri _id;
  final String _type;
  final Map<String, dynamic>? _revocationFields;

  /// The URL of optional unique identifier for the credential status object.
  @override
  Uri get id => _id;

  /// The schema type of credential status.
  @override
  String get type => _type;

  /// Revocation-related fields stored as a generic map (e.g., statusPurpose, statusListIndex).
  Map<String, dynamic>? get revocationFields => _revocationFields;

  /// Creates a [CredentialStatusV1] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  /// The [revocationFields] contains optional revocation-related fields to be included in JSON.
  CredentialStatusV1({
    required Uri id,
    required String type,
    Map<String, dynamic>? revocationFields,
  })  : _id = id,
        _type = type,
        _revocationFields = revocationFields != null
            ? Map.unmodifiable(revocationFields)
            : null;

  /// Creates a [CredentialStatusV1] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory CredentialStatusV1.fromJson(Map<String, dynamic> json) {
    final id = getMandatoryUri(json, 'id');
    final type = getMandatoryString(json, 'type');
    final revocationFields = Map<String, dynamic>.from(json)
      ..remove('id')
      ..remove('type');

    return CredentialStatusV1(
      id: id,
      type: type,
      revocationFields: revocationFields.isEmpty ? null : revocationFields,
    );
  }

  @override
  Map<String, dynamic> toJson() => cleanEmpty({
        'id': id.toString(),
        'type': type,
        if (_revocationFields != null && _revocationFields.isNotEmpty)
          ..._revocationFields,
      });
}
