import '../../../../util/json_util.dart';

abstract interface class _RefreshServiceV1Interface {
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

/// Represents a Mutable refreshService for verifiable credentials following W3C standards.
///
/// It is useful for systems to enable the manual or automatic refresh of an expired verifiable credential.
/// It uses JSON Schema format to refresh credential.
///
/// Example:
/// ```dart
/// final schema = MutableRefreshServiceV1(
///   id: Uri.parse('test-refresh-service-id'),
///   type: 'refresh-type',
/// );
/// ```
class MutableRefreshServiceV1 extends _RefreshServiceV1Interface {
  /// The URL of refresh service
  Uri? id;

  /// type of refresh service
  String? type;

  /// Creates a [MutableRefreshServiceV1] instance.
  ///
  /// The [id] is the URL where refresh service can be found.
  /// The [type] identifies the type of refresher.
  MutableRefreshServiceV1({this.id, this.type});

  /// Creates a [MutableRefreshServiceV1] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory MutableRefreshServiceV1.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getString(json, 'type');

    return MutableRefreshServiceV1(id: id, type: type);
  }
}

/// Represents a refreshService for verifiable credentials following W3C standards.
///
/// It is useful for systems to enable the manual or automatic refresh of an expired verifiable credential.
/// It uses JSON Schema format to refresh credential.
///
/// Example:
/// ```dart
/// final refreshService = RefreshServiceV1(
///   id: Uri.parse('test-refresh-service-id'),
///   type: 'refresh-type',
/// );
/// ```
class RefreshServiceV1 extends _RefreshServiceV1Interface {
  final Uri _id;
  final String _type;

  @override
  Uri get id => _id;

  @override
  String get type => _type;

  /// Creates a [RefreshServiceV1] instance.
  ///
  /// The [id] is the URL where refresh service can be found.
  /// The [type] identifies the type of refresher.
  RefreshServiceV1({required Uri id, required String type})
      : _id = id,
        _type = type;

  /// Creates a [MutableRefreshServiceV1] from JSON data.
  ///
  /// The [json] must contain a 'type' field and may contain an 'id' field.
  factory RefreshServiceV1.fromJson(Map<String, dynamic> json) {
    final id = getMandatoryUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return RefreshServiceV1(id: id, type: type);
  }
}
