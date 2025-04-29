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

class MutableRefreshServiceV1 extends _RefreshServiceV1Interface {
  Uri? id;

  String? type;

  MutableRefreshServiceV1({this.id, this.type});

  factory MutableRefreshServiceV1.fromJson(Map<String, dynamic> json) {
    final id = getUri(json, 'id');
    final type = getString(json, 'type');

    return MutableRefreshServiceV1(id: id, type: type);
  }
}

class RefreshServiceV1 extends _RefreshServiceV1Interface {
  final Uri _id;
  final String _type;

  @override
  Uri get id => _id;

  @override
  String get type => _type;

  RefreshServiceV1({required Uri id, required String type})
      : _id = id,
        _type = type;

  factory RefreshServiceV1.fromJson(Map<String, dynamic> json) {
    final id = getMandatoryUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return RefreshServiceV1(id: id, type: type);
  }
}
