import 'package:ssi/src/util/json_util.dart';

abstract interface class Evidence {
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

class MutableEvidence extends Evidence {
  @override
  Uri? id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  @override
  String? type;

  /// Creates a [MutableEvidence] instance.
  ///
  /// The [domain] is the base URL where the schema is hosted.
  /// The [schema] is the name of the schema without extension.
  /// The [type] is the schema validation type, defaults to 'JsonSchemaValidator2018'.
  MutableEvidence({
    this.id,
    this.type,
  });
}

class ParsedEvidence extends Evidence {
  Uri? _id;
  String _type;

  /// The URL of the schema including domain and filename.
  @override
  Uri? get id => _id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  @override
  String get type => _type;

  ParsedEvidence._(this._id, this._type);

  /// Creates a [MutableEvidence] from JSON data.
  ///
  /// The [json] must contain 'id' and 'type' fields.
  factory ParsedEvidence.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return ParsedEvidence._(id, type);
  }
}
