import '../../../../util/json_util.dart';

/// Represents a schema for verifiable credentials following W3C standards.
///
/// A credential schema defines the structure and constraints of a verifiable credential.
/// It uses JSON Schema format to validate credential data.
///
/// Example:
/// ```dart
/// final schema = CredentialSchema(
///   domain: 'https://example.com/schemas',
///   schema: 'PersonCredential',
/// );
/// ```
class MutableCredentialStatusV2 {
  /// The URL identifier for this status information.
  Uri? id;

  /// The type of status mechanism used.
  String? type;

  /// Creates a [MutableCredentialStatusV2] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  MutableCredentialStatusV2({
    this.id,
    this.type,
  });

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() => cleanEmpty({
        'id': id?.toString(),
        'type': type,
      });
}

class CredentialStatusV2 extends MutableCredentialStatusV2 {
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
