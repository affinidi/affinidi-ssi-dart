import '../../../util/json_util.dart';

abstract interface class _CredentialSchemaInterface {
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

/// Represents a Mutable schema for verifiable credentials following W3C standards.
///
/// A credential schema defines the structure and constraints of a verifiable credential.
/// It uses JSON Schema format to validate credential data.
///
/// Example:
/// ```dart
/// final schema = MutableCredentialSchema(
///   id: Uri.parse('https://example.com/schemas'),
///   type: 'JsonSchemaValidator2018',
/// );
/// ```
class MutableCredentialSchema extends _CredentialSchemaInterface {
  /// The URL of the schema including domain and filename.
  Uri? id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  String? type;

  /// Creates a [MutableCredentialSchema]
  ///
  /// The [id] - is id of credential schema.
  /// The [type]- is schema validation type, defaults to 'JsonSchemaValidator2018'.
  MutableCredentialSchema({
    this.id,
    this.type = 'JsonSchemaValidator2018',
  });

  /// Creates a [MutableCredentialSchema] instance.
  ///
  /// The [domain] is the base URL where the schema is hosted.
  /// The [schema] is the name of the schema without extension.
  /// The [type] is the schema validation type, defaults to 'JsonSchemaValidator2018'.
  factory MutableCredentialSchema.build({
    required String domain,
    required String schema,
    String type = 'JsonSchemaValidator2018',
  }) {
    final id = Uri.parse('$domain/$schema.json');
    return MutableCredentialSchema(id: id, type: type);
  }

  /// Creates a [MutableCredentialSchema] from JSON data.
  ///
  /// The [json] must contain 'id' and 'type' fields.
  factory MutableCredentialSchema.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getString(json, 'type');

    return MutableCredentialSchema(id: id, type: type);
  }
}

/// Represents a Credential Schema for verifiable credentials following W3C standards.
///
/// A credential schema defines the structure and constraints of a verifiable credential.
/// It uses JSON Schema format to validate credential data.
///
/// Example:
/// ```dart
/// final schema = CredentialSchema(
///   id: Uri.parse('https://example.com/schemas'),
///   type: 'JsonSchemaValidator2018',
/// );
/// ```
class CredentialSchema extends _CredentialSchemaInterface {
  final Uri _id;
  final String _type;

  /// The URL of the schema including domain and filename.
  @override
  Uri get id => _id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  @override
  String get type => _type;

  /// Creates a [MutableCredentialSchema]
  ///
  /// The [id] - is id of credential schema.
  /// The [type]- is schema validation type.
  CredentialSchema({required Uri id, required String type})
      : _id = id,
        _type = type;

  /// Creates a [CredentialSchema] from JSON data.
  ///
  /// The [json] must contain 'id' and 'type' fields.
  factory CredentialSchema.fromJson(Map<String, dynamic> json) {
    final id = getMandatoryUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return CredentialSchema(id: id, type: type);
  }
}
