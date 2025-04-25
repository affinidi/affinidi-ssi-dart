import '../../../../util/json_util.dart';

class MutableRefreshServiceV1 {
  Uri? id;

  String? type;

  MutableRefreshServiceV1({this.id, this.type});
  Map<String, dynamic> toJson() => {'id': id?.toString(), 'type': type};
}

class RefreshServiceV1 extends MutableRefreshServiceV1 {
  final Uri _id;
  final String _type;

  @override
  Uri get id => _id;

  @override
  String get type => _type;

  RefreshServiceV1._(this._id, this._type);

  factory RefreshServiceV1.fromJson(Map<String, dynamic> json) {
    final id = getMandatoryUri(json, 'id');
    final type = getMandatoryString(json, 'type');

    return RefreshServiceV1._(id, type);
  }
}
