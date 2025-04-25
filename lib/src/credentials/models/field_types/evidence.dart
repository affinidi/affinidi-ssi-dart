import '../../../util/json_util.dart';

class MutableEvidence {
  Uri? id;

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  String? type;

  MutableEvidence({
    this.id,
    this.type,
  });

  /// Converts this schema to a JSON-serializable map.
  ///
  /// Returns a map containing 'id' and 'type' fields.
  Map<String, dynamic> toJson() => cleanEmpty({
        'id': id?.toString(),
        'type': type,
      });
}

class Evidence extends MutableEvidence {
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

  Evidence({Uri? id, required String type})
      : _id = id,
        _type = type;

  /// Creates an [Evidence] from JSON data.
  ///
  /// The [json] must contain 'id' and 'type' fields.
  factory Evidence.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return Evidence(id: id, type: type);
  }
}
