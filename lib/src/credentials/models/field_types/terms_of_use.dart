import '../../../util/json_util.dart';

abstract interface class _TermsOfUseInterface {
  Uri? get id;
  String? get type;

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() =>
      cleanEmpty({'id': id?.toString(), 'type': type});
}

class MutableTermsOfUse extends _TermsOfUseInterface {
  Uri? id;

  String? type;

  MutableTermsOfUse({
    this.id,
    this.type,
  });

  /// Creates a [TermsOfUse] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory MutableTermsOfUse.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getString(json, 'type');

    return MutableTermsOfUse(id: id, type: type);
  }
}

class TermsOfUse extends _TermsOfUseInterface {
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
