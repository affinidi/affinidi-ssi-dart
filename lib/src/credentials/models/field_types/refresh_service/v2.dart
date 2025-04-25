import '../../../../util/json_util.dart';

abstract interface class RefreshServiceV2 {
  String? get type;

  Map<String, dynamic> toJson() => {'type': type};
}

class MutableRefreshServiceV2 extends RefreshServiceV2 {
  @override
  String? type;

  MutableRefreshServiceV2({this.type});
}

class ParsedRefreshServiceV2 extends RefreshServiceV2 {
  final String _type;

  @override
  String get type => _type;

  ParsedRefreshServiceV2._(this._type);

  factory ParsedRefreshServiceV2.fromJson(Map<String, dynamic> json) {
    final type = getMandatoryString(json, 'type');

    return ParsedRefreshServiceV2._(type);
  }
}
