import '../../../util/json_util.dart';

abstract interface class TermsOfUse {
  Uri? get id;

  String? get type;

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() => {
        'id': id?.toString(),
        'type': type,
      };
}

class MutableTermsOfUse extends TermsOfUse {
  @override
  Uri? id;

  @override
  String? type;

  MutableTermsOfUse({
    this.id,
    this.type,
  });
}

class ParsedTermsOfUse extends TermsOfUse {
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

  ParsedTermsOfUse._(this._id, this._type);

  /// Creates a [ParsedTermsOfUse] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory ParsedTermsOfUse.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return ParsedTermsOfUse._(id, type);
  }
}
