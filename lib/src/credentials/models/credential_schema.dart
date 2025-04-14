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
class CredentialSchema {
  /// The URL of the schema including domain and filename.
  final String id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  final String type;

  /// Creates a [CredentialSchema] instance.
  ///
  /// The [domain] is the base URL where the schema is hosted.
  /// The [schema] is the name of the schema without extension.
  /// The [type] is the schema validation type, defaults to 'JsonSchemaValidator2018'.
  CredentialSchema({
    required String domain,
    required String schema,
    this.type = 'JsonSchemaValidator2018',
  }) : id = '$domain/$schema.json';

  /// Creates a [CredentialSchema] from JSON data.
  ///
  /// The [json] must contain 'id' and 'type' fields.
  CredentialSchema.fromJson(Map<String, dynamic> json)
      : id = json['id'] as String,
        type = json['type'] as String;

  /// Converts this schema to a JSON-serializable map.
  ///
  /// Returns a map containing 'id' and 'type' fields.
  Map<String, dynamic> toJson() => {
        'id': id,
        'type': type,
      };
}
