import '../../../util/json_util.dart';

abstract interface class _EvidenceInterface {
  Uri? get id;
  String? get type;

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() => cleanEmpty({
        'id': id?.toString(),
        'type': type,
      });
}

/// Represents a Mutable Evidence for verifiable credentials following W3C standards.
///
/// Evidence can be included by an issuer to provide the verifier with
/// additional supporting information in a verifiable credential
/// It uses JSON Schema format to check evidence.
///
/// Example:
/// ```dart
/// final evidence = MutableEvidence(
///   id: Uri.parse('test-evidence-id'),
///   'type': 'Evidence1',
/// );
/// ```
class MutableEvidence extends _EvidenceInterface {
  /// the URL of  unique identifier for the evidence object
  Uri? id;

  /// the type of evidence information
  String? type;

  /// Creates a [MutableEvidence]
  ///
  /// The [id] - is id for the evidence object.
  /// The [type]- is type of evidence information.
  MutableEvidence({
    this.id,
    this.type,
  });

  /// Creates a [MutableEvidence] from JSON data.
  ///
  /// The [json] must contain 'id' and 'type' fields.
  factory MutableEvidence.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getString(json, 'type');

    return MutableEvidence(id: id, type: type);
  }
}

/// Represents a Evidence for verifiable credentials following W3C standards.
///
/// Evidence can be included by an issuer to provide the verifier with
/// additional supporting information in a verifiable credential
/// It uses JSON Schema format to check evidence.
///
/// Example:
/// ```dart
/// final evidence = Evidence(
///   id: Uri.parse('test-evidence-id'),
///   'type': 'Evidence1',
/// );
/// ```
class Evidence extends _EvidenceInterface {
  final Uri? _id;
  final String _type;

  /// the URL of  unique identifier for the evidence object
  @override
  Uri? get id => _id;

  /// the type of evidence information
  @override
  String get type => _type;

  /// Creates a [Evidence]
  ///
  /// The [id] - is id for the evidence object.
  /// The [type]- is type of evidence information.
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
