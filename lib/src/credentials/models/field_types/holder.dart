import 'package:ssi/src/util/json_util.dart';

abstract interface class Holder {
  Uri? get id;

  Map<String, dynamic> toJson() => {
        'id': id?.toString(),
      };
}

class MutableHolder extends Holder {
  @override
  Uri id;

  MutableHolder(this.id);
}

class ParsedHolder extends Holder {
  Uri _id;

  @override
  Uri get id => _id;

  ParsedHolder._(this._id);

  factory ParsedHolder.fromJson(dynamic json) {
    Uri id;

    if (json is String) {
      id = Uri.parse(json);
    } else {
      id = getMandatoryUri(json, 'id');
    }

    return ParsedHolder._(id);
  }
}
