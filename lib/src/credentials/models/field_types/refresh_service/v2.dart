import '../../../../util/json_util.dart';

class MutableRefreshServiceV2 {
  String? type;

  MutableRefreshServiceV2({this.type});
  Map<String, dynamic> toJson() => {'type': type};
}

class RefreshServiceV2 extends MutableRefreshServiceV2 {
  final String _type;

  @override
  String get type => _type;

  RefreshServiceV2._(this._type);

  factory RefreshServiceV2.fromJson(Map<String, dynamic> json) {
    final type = getMandatoryString(json, 'type');

    return RefreshServiceV2._(type);
  }
}
