import '../../../../util/json_util.dart';

abstract interface class RefreshServiceV1 {
  Uri? get id;
  String? get type;

  Map<String, dynamic> toJson() => {'id': id?.toString(), 'type': type};
}

class MutableRefreshServiceV1 extends RefreshServiceV1 {
  @override
  Uri? id;

  @override
  String? type;

  MutableRefreshServiceV1({this.id, this.type});
}

class ParsedRefreshServiceV1 extends RefreshServiceV1 {
  final Uri _id;
  final String _type;

  @override
  Uri get id => _id;

  @override
  String get type => _type;

  ParsedRefreshServiceV1._(this._id, this._type);

  factory ParsedRefreshServiceV1.fromJson(Map<String, dynamic> json) {
    final id = getMandatoryUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return ParsedRefreshServiceV1._(id, type);
  }
}
