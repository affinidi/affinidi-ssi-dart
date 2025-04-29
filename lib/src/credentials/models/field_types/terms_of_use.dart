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

/// Represents a Mutable termsOfUse for verifiable credentials following W3C standards.
///
/// Terms of Use  specify the conditions and restrictions under which a credential or presentation can be used.
///
/// Example:
/// ```dart
/// final schema = MutableTermsOfUse(
///   id: Uri.parse('test-terms-of-use-id'),
///   type: 'TrustFrameworkPolicy'
/// );
/// ```
class MutableTermsOfUse extends _TermsOfUseInterface {
  /// the URL of unique identifier for termsOfUse
  Uri? id;

  /// type of terms of user for which this crendetial issued
  String? type;

  /// Creates a [MutableTermsOfUse]
  ///
  /// The [id] - is id of terms of use.
  /// The [type]- is type of terms.
  MutableTermsOfUse({
    this.id,
    this.type,
  });

  /// Creates a [MutableTermsOfUse] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory MutableTermsOfUse.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getString(json, 'type');

    return MutableTermsOfUse(id: id, type: type);
  }
}

/// Represents a termsOfUse for verifiable credentials following W3C standards.
///
/// Terms of Use  specify the conditions and restrictions under which a credential or presentation can be used.
///
/// Example:
/// ```dart
/// final schema = TermsOfUse(
///   id: Uri.parse('test-terms-of-use-id'),
///   type: 'TrustFrameworkPolicy'
/// );
/// ```
class TermsOfUse extends _TermsOfUseInterface {
  final Uri? _id;
  final String _type;

  /// the URL of unique identifier for termsOfUse
  @override
  Uri? get id => _id;

  /// type of terms of user for which this crendetial issued
  @override
  String get type => _type;

  /// Creates a [MutableTermsOfUse]
  ///
  /// The [id] - is id of terms of use.
  /// The [type]- is type of terms.
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
