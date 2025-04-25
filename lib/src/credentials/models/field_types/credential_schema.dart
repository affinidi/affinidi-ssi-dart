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
abstract interface class CredentialSchema {
  /// The URL of the schema including domain and filename.
  Uri? get id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  String? get type;

  /// Converts this schema to a JSON-serializable map.
  ///
  /// Returns a map containing 'id' and 'type' fields.
  Map<String, dynamic> toJson() => {
        'id': id?.toString(),
        'type': type,
      };
}

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
class MutableCredentialSchema extends CredentialSchema {
  /// The URL of the schema including domain and filename.
  @override
  Uri? id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  @override
  String? type;

  /// Creates a [MutableCredentialSchema] instance.
  ///
  /// The [domain] is the base URL where the schema is hosted.
  /// The [schema] is the name of the schema without extension.
  /// The [type] is the schema validation type, defaults to 'JsonSchemaValidator2018'.
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
}

class ParsedCredentialSchema extends CredentialSchema {
  Uri _id;
  String _type;

  /// The URL of the schema including domain and filename.
  @override
  Uri get id => _id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  @override
  String get type => _type;

  ParsedCredentialSchema._(this._id, this._type);

  /// Creates a [MutableCredentialSchema] from JSON data.
  ///
  /// The [json] must contain 'id' and 'type' fields.
  factory ParsedCredentialSchema.fromJson(Map<String, dynamic> json) {
    final id = getMandatoryUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return ParsedCredentialSchema._(id, type);
  }
}
