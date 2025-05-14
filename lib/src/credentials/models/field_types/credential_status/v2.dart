import '../../../../util/json_util.dart';

abstract interface class _CredentialStatusV2Interface {
  Uri? get id;
  String? get type;

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() => cleanEmpty({
        'id': id?.toString(),
        'type': type,
      });
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
/// );
/// ```
class MutableCredentialStatusV2 extends _CredentialStatusV2Interface {
  /// The URL identifier for this status information.
  @override
  Uri? id;

  /// The type of status mechanism used.
  @override
  String? type;

  /// Creates a [MutableCredentialStatusV2] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  MutableCredentialStatusV2({
    this.id,
    this.type,
  });

  /// Creates a [MutableCredentialStatusV2] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory MutableCredentialStatusV2.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getString(json, 'type');

    return MutableCredentialStatusV2(id: id, type: type);
  }
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
/// );
/// ```
class CredentialStatusV2 extends _CredentialStatusV2Interface {
  final Uri? _id;
  final String _type;

  /// The URL of the schema including domain and filename.
  @override
  Uri? get id => _id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  @override
  String get type => _type;

  /// Creates a [CredentialStatusV2] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  CredentialStatusV2({Uri? id, required String type})
      : _id = id,
        _type = type;

  /// Creates a [CredentialStatusV2] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory CredentialStatusV2.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return CredentialStatusV2(id: id, type: type);
  }
}
