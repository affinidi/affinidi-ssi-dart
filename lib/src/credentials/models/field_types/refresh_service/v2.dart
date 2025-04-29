import '../../../../util/json_util.dart';

abstract interface class _RefreshServiceV2Interface {
  String? get type;

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() => cleanEmpty({'type': type});
}

class MutableRefreshServiceV2 extends _RefreshServiceV2Interface {
  String? type;

  MutableRefreshServiceV2({this.type});

  factory MutableRefreshServiceV2.fromJson(Map<String, dynamic> json) {
    final type = getString(json, 'type');

    return MutableRefreshServiceV2(type: type);
  }
}

class RefreshServiceV2 extends _RefreshServiceV2Interface {
  final String _type;

  @override
  String get type => _type;

  RefreshServiceV2({required String type}) : _type = type;

  factory RefreshServiceV2.fromJson(Map<String, dynamic> json) {
    final type = getMandatoryString(json, 'type');

    return RefreshServiceV2(type: type);
  }
}
