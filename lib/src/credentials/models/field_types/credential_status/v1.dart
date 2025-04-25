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
class MutableCredentialStatusV1 {
  /// The URL identifier for this status information.
  Uri? id;

  /// The type of status mechanism used.
  String? type;

  /// Creates a [MutableCredentialStatusV1] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  MutableCredentialStatusV1({
    this.id,
    this.type,
  });

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() => {
        'id': id?.toString(),
        'type': type,
      };
}

class CredentialStatusV1 extends MutableCredentialStatusV1 {
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

  CredentialStatusV1._(this._id, this._type);

  /// Creates a [CredentialStatusV1] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory CredentialStatusV1.fromJson(Map<String, dynamic> json) {
    final id = getMandatoryUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return CredentialStatusV1._(id, type);
  }
}
