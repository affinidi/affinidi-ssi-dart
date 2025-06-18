import '../../../../util/json_util.dart';

abstract interface class _CredentialStatusV2Interface {
  Uri? get id;
  String? get type;

  /// Converts this status to a JSON-serializable map.
  Map<String, dynamic> toJson();
}

/// Represents a Mutable Credential Status for verifiable credentials following W3C standards.
///
/// This specification defines the credentialStatus property for discovering information related
/// to the status of a verifiable credential, such as whether it is suspended or revoked.
///
/// Example:
/// ```dart
/// final credentialStatus = MutableCredentialStatusV2(
///   id: Uri.parse('https://license.example/credentials/status/84#14278'),
///   type: 'BitstringStatusListEntry',
///   revocationFields: {'revocationListIndex': '94567', 'revocationListCredential': 'https://pharma.example.com/credentials/status/3'},
/// );
/// ```
class MutableCredentialStatusV2 extends _CredentialStatusV2Interface {
  /// The URL identifier for this status information.
  @override
  Uri? id;

  /// The type of status mechanism used.
  @override
  String? type;

  /// Revocation-related fields stored as a generic map (e.g., statusPurpose, statusListIndex).
  Map<String, dynamic>? revocationFields;

  /// Creates a [MutableCredentialStatusV2] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  /// The [revocationFields] contains optional revocation-related fields to be included in JSON.
  MutableCredentialStatusV2({
    this.id,
    this.type,
    this.revocationFields,
  });

  /// Creates a [MutableCredentialStatusV2] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory MutableCredentialStatusV2.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getString(json, 'type');

    // Capture all fields except 'id' and 'type' in revocationFields
    final revocationFields = Map<String, dynamic>.from(json)
      ..remove('id')
      ..remove('type');

    return MutableCredentialStatusV2(
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
/// to the status of a verifiable credential, such as whether it is suspended or revoked.
///
/// Example:
/// ```dart
/// final credentialStatus = CredentialStatusV2(
///   id: Uri.parse('https://license.example/credentials/status/84#14278'),
///   type: 'BitstringStatusListEntry',
///   revocationFields: {'revocationListIndex': '94567', 'revocationListCredential': 'https://pharma.example.com/credentials/status/3'},
/// );
/// ```
class CredentialStatusV2 extends _CredentialStatusV2Interface {
  final Uri? _id;
  final String _type;
  final Map<String, dynamic>? _revocationFields;

  /// The URL of the schema including domain and filename.
  @override
  Uri? get id => _id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  @override
  String get type => _type;

  /// Revocation-related fields stored as a generic map (e.g., statusPurpose, statusListIndex).
  Map<String, dynamic>? get revocationFields => _revocationFields;

  /// Creates a [CredentialStatusV2] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  /// The [revocationFields] contains optional revocation-related fields to be included in JSON.
  CredentialStatusV2({
    Uri? id,
    required String type,
    Map<String, dynamic>? revocationFields,
  })  : _id = id,
        _type = type,
        _revocationFields = revocationFields != null
            ? Map.unmodifiable(revocationFields)
            : null;

  /// Creates a [CredentialStatusV2] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory CredentialStatusV2.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getMandatoryString(json, 'type');
    final revocationFields = Map<String, dynamic>.from(json)
      ..remove('id')
      ..remove('type');

    return CredentialStatusV2(
      id: id,
      type: type,
      revocationFields: revocationFields.isEmpty ? null : revocationFields,
    );
  }

  @override
  Map<String, dynamic> toJson() => cleanEmpty({
        'id': id?.toString(),
        'type': type,
        if (_revocationFields != null && _revocationFields.isNotEmpty)
          ..._revocationFields,
      });
}
