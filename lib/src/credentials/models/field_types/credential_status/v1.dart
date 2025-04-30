import '../../../../util/json_util.dart';

abstract interface class _CredentialStatusV1Interface {
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
/// to the status of a verifiable credential, such as whether it is revoked or not.
/// It uses JSON Schema format to check status of credential.
///
/// Example:
/// ```dart
/// final credentialStatus = MutableCredentialStatusV1(
///   id: Uri.parse('test-credential-status-id'),
///   type: 'BitstringStatusListEntry',
/// );
/// ```
class MutableCredentialStatusV1 extends _CredentialStatusV1Interface {
  /// The URL of optional unique identifier for the credential status object.
  Uri? id;

  /// The schema type of credential status.
  String? type;

  /// Creates a [MutableCredentialStatusV1] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  MutableCredentialStatusV1({
    this.id,
    this.type,
  });

  /// Creates a [MutableCredentialStatusV1] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory MutableCredentialStatusV1.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getString(json, 'type');

    return MutableCredentialStatusV1(id: id, type: type);
  }
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
/// );
/// ```
class CredentialStatusV1 extends _CredentialStatusV1Interface {
  final Uri _id;
  final String _type;

  /// The URL of optional unique identifier for the credential status object.
  @override
  Uri get id => _id;

  /// The schema type of credential status.
  @override
  String get type => _type;

  /// Creates a [CredentialStatusV1] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  CredentialStatusV1({required Uri id, required String type})
      : _id = id,
        _type = type;

  /// Creates a [CredentialStatusV1] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory CredentialStatusV1.fromJson(Map<String, dynamic> json) {
    final id = getMandatoryUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return CredentialStatusV1(id: id, type: type);
  }
}
