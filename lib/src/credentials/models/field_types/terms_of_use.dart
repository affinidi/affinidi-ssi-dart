import '../../../util/json_util.dart';

class MutableTermsOfUse {
  Uri? id;

  String? type;

  MutableTermsOfUse({
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

class TermsOfUse extends MutableTermsOfUse {
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

  TermsOfUse({Uri? id, required String type})
      : _id = id,
        _type = type;

  /// Creates a [TermsOfUse] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory TermsOfUse.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return TermsOfUse(id: id, type: type);
  }
}
