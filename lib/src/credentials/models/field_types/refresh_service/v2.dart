import '../../../../util/json_util.dart';

abstract interface class _RefreshServiceV2Interface {
  String? get type;

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() => cleanEmpty({'type': type});
}

/// Represents a Mutable refreshService for verifiable credentials following W3C standards.
///
/// It is useful for systems to enable the manual or automatic refresh of an expired verifiable credential.
///
/// Example:
/// ```dart
/// final schema = MutableRefreshServiceV2(
///   type: 'ManualRefreshService2021',
/// );
/// ```
class MutableRefreshServiceV2 extends _RefreshServiceV2Interface {
  /// type of refresh service
  String? type;

  /// Creates a [MutableRefreshServiceV2] instance.
  ///
  /// The [type] identifies the type of refresher.
  MutableRefreshServiceV2({this.type});

  /// Creates a [MutableRefreshServiceV2] from JSON data.
  ///
  /// The [json] must contain a 'type' field.
  factory MutableRefreshServiceV2.fromJson(Map<String, dynamic> json) {
    final type = getString(json, 'type');

    return MutableRefreshServiceV2(type: type);
  }
}

/// Represents a refreshService for verifiable credentials following W3C standards.
///
/// It is useful for systems to enable the manual or automatic refresh of an expired verifiable credential.
///
/// Example:
/// ```dart
/// final refreshService = RefreshServiceV2(
///   type: 'ManualRefreshService2021',
/// );
/// ```
class RefreshServiceV2 extends _RefreshServiceV2Interface {
  final String _type;

  @override
  String get type => _type;

  /// Creates a [RefreshServiceV2] instance.
  ///
  /// The [type] identifies the type of refresher.
  RefreshServiceV2({required String type}) : _type = type;

  /// Creates a [RefreshServiceV2] from JSON data.
  ///
  /// The [json] must contain a 'type' field.
  factory RefreshServiceV2.fromJson(Map<String, dynamic> json) {
    final type = getMandatoryString(json, 'type');

    return RefreshServiceV2(type: type);
  }
}
