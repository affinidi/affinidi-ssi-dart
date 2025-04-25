import '../../../util/json_util.dart';

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
class MutableCredentialSchema {
  /// The URL of the schema including domain and filename.
  Uri? id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  String? type;

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

  /// Converts this schema to a JSON-serializable map.
  ///
  /// Returns a map containing 'id' and 'type' fields.
  Map<String, dynamic> toJson() => cleanEmpty({
        'id': id?.toString(),
        'type': type,
      });
}

class CredentialSchema extends MutableCredentialSchema {
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

  CredentialSchema({required Uri id, required String type})
      : _id = id,
        _type = type;

  /// Creates a [MutableCredentialSchema] from JSON data.
  ///
  /// The [json] must contain 'id' and 'type' fields.
  factory CredentialSchema.fromJson(Map<String, dynamic> json) {
    final id = getMandatoryUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return CredentialSchema(id: id, type: type);
  }
}
