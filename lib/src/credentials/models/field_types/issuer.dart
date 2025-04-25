import 'package:ssi/src/util/json_util.dart';

abstract interface class Issuer {
  Uri? get id;

  Map<String, dynamic> toJson() => {
        'id': id?.toString(),
      };
}

class MutableIssuer extends Issuer {
  @override
  Uri id;

  MutableIssuer(this.id);
}

class ParsedIssuer extends Issuer {
  Uri _id;

  @override
  Uri get id => _id;

  ParsedIssuer._(this._id);

  factory ParsedIssuer.fromJson(dynamic json) {
    Uri id;

    if (json is String) {
      id = Uri.parse(json);
    } else {
      id = getMandatoryUri(json, 'id');
    }

    return ParsedIssuer._(id);
  }
}
